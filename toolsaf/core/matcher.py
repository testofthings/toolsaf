"""Match events into system model"""

from typing import Self, Tuple, Dict

from dataclasses import dataclass

from toolsaf.common.address import AnyAddress, EndpointAddress, IPAddress
from toolsaf.common.basics import ExternalActivity, Status
from toolsaf.core.matcher_engine import FlowMatcher, MatcherEngine
from toolsaf.core.model import IoTSystem, Connection, Host, Addressable, EvidenceNetworkSource, ModelListener
from toolsaf.common.traffic import Flow, EvidenceSource
from toolsaf.common.verdict import Verdict


class SystemMatcher(ModelListener):
    """Match system model"""
    def __init__(self, system: IoTSystem) -> None:
        self.system = system
        self.contexts: Dict[EvidenceSource, MatchingContext] = {}
        system.model_listeners.append(self)

    def reset(self) -> Self:
        """Reset the model"""
        self.contexts.clear()
        self.system.reset()
        return self

    def address_change(self, host: Host) -> None:
        for ctx in self.contexts.values():
            ctx.engine.update_host(host)

    def connection(self, flow: Flow) -> Connection:
        """Find the connection matching the given flow"""
        return self.connection_w_ends(flow)[0]

    def connection_w_ends(self, flow: Flow) -> Tuple[Connection, AnyAddress, AnyAddress, bool]:
        """Find the connection matching the given flow, return also endpoint addresses"""
        source = flow.evidence.source
        ctx = self._get_context(source)
        m = ctx.get_connection(flow)
        return m.connection, m.source, m.target, m.reply

    def endpoint(self, address: AnyAddress, source: EvidenceSource) -> Addressable:
        """Find endpoint by address"""
        ctx = self._get_context(source)
        e = ctx.get_endpoint(address)
        return e

    def _get_context(self, source: EvidenceSource) -> 'MatchingContext':
        """Get matching context for source"""
        ctx = self.contexts.get(source)
        if ctx is None:
            ctx = MatchingContext(self, source)
            self.contexts[source] = ctx
        return ctx


@dataclass(frozen=True)
class ConnectionMatch:
    """Matched connection"""
    connection: Connection
    source: AnyAddress
    target: AnyAddress
    reply: bool = False

    def __repr__(self) -> str:
        return f"{self.connection}"

@dataclass(frozen=True)
class AddressMatch:
    """Matched address"""
    endpoint: Addressable
    address: AnyAddress


class MatchingContext:
    """Matching context"""
    def __init__(self, system: SystemMatcher, source: EvidenceSource) -> None:
        self.system = system
        self.observed: Dict[Flow, ConnectionMatch] = {}
        self.engine = MatcherEngine(system.system)

        # load system model into matching engine
        for c in system.system.get_connections():
            self.engine.add_connection(c)
        for h in system.system.get_hosts():
            self.engine.add_host(h)

        # load evidence source -specific address mappings
        self.source = source if isinstance(source, EvidenceNetworkSource) else None
        if self.source:
            for ad, ent in self.source.address_map.items():
                self.engine.add_address_mapping(ad, ent)

            # FIXME: Add activity map support
            assert not self.source.activity_map, "Activity map not supported in matcher engine"
            # check if exteranal activity changes for some entities
            # for me in itertools.chain(*self.endpoints.values()):
            #     fs = self.source.activity_map.get(me.entity)
            #     if fs is not None:
            #         me.external_activity = fs

    def get_connection(self, flow: Flow) -> ConnectionMatch:
        """Get connection matching the given flow"""
        c = self.observed.get(flow)
        if c:
            return c

        matcher = FlowMatcher(self.engine, flow)
        conn = matcher.get_connection()
        source_add, target_add = matcher.get_host_addresses()
        if isinstance(conn, Connection):
            assert source_add is not None and target_add is not None
            c = ConnectionMatch(conn, source_add, target_add, matcher.reverse)
            self.observed[flow] = c
            return c
        source, target = conn

        # no connection, must create new
        if source is None:
            # no suitable source, make new
            source, source_add = self.new_endpoint(flow, target=False)
        if target is None:
            # no suitable target, make new
            target, target_add = self.new_endpoint(flow, target=True)
        assert source_add is not None and target_add is not None

        c = self.new_connection((source, source_add), (target, target_add))
        self.observed[flow] = c
        return c

    def get_endpoint(self, address: AnyAddress) -> Addressable:
        """Get endpoint by address, create new if not found"""
        host = self.engine.find_endpoint(address)
        net = self.system.system.get_networks_for(address)
        if host:
            if not address.get_protocol_port():
                return host
            e = host.get_endpoint(address, at_network=net[0] if net else None)
            self.engine.add_host(e)  # if created
            return e
        # no such host
        e = self.system.system.get_endpoint(address)
        self.engine.add_host(e)
        return e


    def new_endpoint(self, flow: Flow, target: bool) -> Tuple[Addressable, AnyAddress]:
        """Create a new endpoint host"""
        system = self.system.system
        stack = flow.stack(target)
        use_ad = stack[0]
        for ad in stack[1:]:
            if isinstance(ad, IPAddress):
                if system.is_external(ad) or ad.is_multicast():
                    use_ad = ad  # must use the IP address
                    break
            if use_ad.is_null() and not ad.is_null():
                use_ad = ad  # prefer non-null address
        host = system.get_endpoint(use_ad, at_network=flow.network)
        self.engine.add_host(host)
        # return the matching address
        match_address = EndpointAddress(use_ad, flow.protocol, flow.port(target))
        return host, match_address

    def new_connection(self, source: Tuple[Addressable, AnyAddress], target: Tuple[Addressable, AnyAddress]) \
        -> ConnectionMatch:
        """Create new unexpected connection"""
        system = self.system.system
        c = system.new_connection(source, target)
        self.set_connection_status(c, source, target)
        self.engine.add_connection(c)
        return ConnectionMatch(c, source[1], target[1])

    def set_connection_status(self, connection: Connection, source: Tuple[Addressable, AnyAddress],
                              target: Tuple[Addressable, AnyAddress]) -> Connection:
        """Set status for unexpected connection"""
        c = connection
        c.status = Status.UNEXPECTED

        def set_external(e: Addressable) -> None:
            if e.status == Status.UNEXPECTED and e.get_expected_verdict() == Verdict.INCON:
                # entity is fresh and unexpected, make it external
                e.status = Status.EXTERNAL
                if isinstance(e.parent, Addressable):
                    set_external(e.parent)

        # new connection status by external activity policies and reply status
        source_act = source[0].external_activity
        target_act = target[0].external_activity
        if source_act > ExternalActivity.BANNED and target_act > ExternalActivity.BANNED:
            # unexpected connections may be allowed
            reply = c.source == target[0]
            if source_act >= ExternalActivity.UNLIMITED:
                # source is free to make connections
                c.status = Status.EXTERNAL
                set_external(c.source)
            elif reply and source_act >= ExternalActivity.OPEN:
                # source can make replies
                c.status = Status.EXTERNAL
                set_external(c.source)
            if c.status == Status.EXTERNAL and target_act >= ExternalActivity.PASSIVE:
                # target is free receive connections
                set_external(c.target)
        return c

    # def create_unknown_service(self, match: ConnectionMatch) -> None:
    #     """Create an unknown service due observing reply from it"""
    #     system = self.system.system
    #     conn = match.connection
    #     target_h = conn.target
    #     assert isinstance(target_h, Host)
    #     n_service_ep = match.target.address
    #     assert conn not in target_h.connections, "Connection already added to target host"
    #     assert isinstance(n_service_ep, EndpointAddress), "Expected endpoint address from observation cache"

    #     # change connection to point the new service
    #     n_service = target_h.get_endpoint(n_service_ep)  # NOTE: Network not specified - how can there be many?
    #     if n_service is None:
    #         n_service = target_h.create_service(n_service_ep)
    #     assert isinstance(n_service, Service)

    #     if target_h.external_activity >= ExternalActivity.UNLIMITED and conn.status == Status.EXTERNAL \
    #         and n_service.status == Status.UNEXPECTED:
    #         # host is free to provide unlisted services
    #         n_service.status = Status.EXTERNAL
    #     target_h.connections.append(conn)
    #     networks = target_h.get_networks_for(n_service_ep.get_host())
    #     for nw in networks:
    #         # for each network, the host is in
    #         for ep in self.endpoints[AddressAtNetwork(n_service_ep.get_host(), nw)]:
    #             if ep.entity == target_h:
    #                 ep.add_service(n_service)
    #     conn.target = n_service
    #     # create new connection for connections from same the source to the same target host, but different port
    #     new_c = None
    #     new_obs: Dict[Flow, ConnectionMatch] = {}
    #     for of, om in self.observed.items():
    #         if om.connection == conn and om.target.address != n_service_ep:
    #             # same connection, but different target address
    #             if new_c is None:
    #                 new_c = system.new_connection((conn.source, om.source.address), (target_h, om.target.address))
    #                 self.set_connection_status(new_c, om.source, om.target)
    #             else:
    #                 system.connections[om.source.address, om.target.address] = new_c
    #             new_m = ConnectionMatch(new_c, om.source, om.target, om.reply)
    #             new_obs[of] = new_m
    #     self.observed.update(new_obs)
