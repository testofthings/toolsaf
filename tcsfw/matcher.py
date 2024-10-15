"""Match events into system model"""

import itertools
from typing import Self, Tuple, Dict, Optional, Set, List, Iterable

from tcsfw.address import AddressAtNetwork, AnyAddress, EndpointAddress, IPAddress, Addresses, DNSName
from tcsfw.basics import ExternalActivity, Status
from tcsfw.model import IoTSystem, Connection, Host, Addressable, Service, EvidenceNetworkSource, ModelListener
from tcsfw.property import Properties
from tcsfw.traffic import Flow, EvidenceSource, IPFlow
from tcsfw.verdict import Verdict


class SystemMatcher(ModelListener):
    """Match system model"""
    def __init__(self, system: IoTSystem):
        self.system = system
        self.engines: Dict[EvidenceSource, MatchEngine] = {}
        self.host_addresses = {c: c.addresses.copy() for c in system.children}
        system.model_listeners.append(self)

    def reset(self) -> 'SystemMatcher':
        """Reset the model"""
        self.engines.clear()
        self.system.reset()
        return self

    def address_change(self, host: Host):
        ads = self.host_addresses.get(host, set())
        dns = any(isinstance(a, DNSName) for a in host.addresses)
        if not dns or ads == host.addresses:
            return  # only allowed change is learning IP by DNS
        self.host_addresses[host] = host.addresses.copy()

        for eng in self.engines.values():
            eng.update_addresses(host, ads)

    def connection(self, flow: Flow) -> Connection:
        """Find the connection matching the given flow"""
        return self.connection_w_ends(flow)[0]

    def connection_w_ends(self, flow: Flow) -> Tuple[Connection, AnyAddress, AnyAddress, bool]:
        """Find the connection matching the given flow, return also endpoint addresses"""
        source = flow.evidence.source
        engine = self.engines.get(source)
        if engine is None:
            engine = MatchEngine(self, source)
            self.engines[source] = engine
        m = engine.get_connection(flow)
        return m.connection, m.source.address, m.target.address, m.reply


class MatchFlow:
    """Flow to match"""
    def __init__(self, flow: Flow):
        self.flow = flow
        source = flow.evidence.source
        self.address_map: Dict[AnyAddress, Addressable] = {}
        if isinstance(source, EvidenceNetworkSource):
            # flow source gives information about mapping address -> entity
            self.address_map = source.address_map
        # cache endpoint match results
        self.cache: Dict[Tuple[Addressable, bool], bool] = {}

    def __repr__(self):
        return self.flow.__repr__()


class AddressMatch:
    """A match to address and endpoint"""
    def __init__(self, address: AnyAddress, endpoint: 'MatchEndpoint'):
        assert isinstance(address, EndpointAddress)
        self.address = address
        self.endpoint = endpoint

    def __repr__(self):
        return f"{self.endpoint.entity.name} ? {self.address}"


class ConnectionMatch:
    """A match to a connection"""
    def __init__(self, connection: Connection, source: AddressMatch, target: AddressMatch, reply=False):
        self.connection = connection
        self.source = source
        self.target = target
        self.reply = reply

    def __repr__(self):
        se, te = self.connection.source.long_name(), self.connection.target.long_name()
        if self.reply:
            return f"{self.source.address} << {self.target.address} # {se} << {te}"
        return f"{self.source.address} >> {self.target.address} # {se} >> {te}"


class ConnectionFinder:
    """Try to find the connection from given endpoints"""
    def __init__(self, system: SystemMatcher, unexpected: bool):
        self.system = system
        self.sources: Dict[Addressable, AddressMatch] = {}
        self.targets: Dict[Addressable, AddressMatch] = {}
        self.unexpected = unexpected  # also check unexpected connections?

    def add_source(self, source: AddressMatch) -> Optional[ConnectionMatch]:
        """Add connection source, priority order, return connection if found"""
        if source.endpoint.entity in self.sources:
            return None
        m = source.endpoint.match_connection(source, self.targets.values(), self.unexpected)
        if m:
            return m
        self.sources[source.endpoint.entity] = source
        return None

    def add_target(self, target: AddressMatch) -> Optional[ConnectionMatch]:
        """Add connection target, priority order, return connection if found"""
        if target.endpoint.entity in self.targets:
            return None
        for s in self.sources.values():
            m = s.endpoint.match_connection(s, [target], self.unexpected)
            if m:
                return m
        self.targets[target.endpoint.entity] = target
        return None

    def add_matches(self, matches: List[AddressMatch], target: bool):
        """Add list of source or target ends, priority order"""
        for em in matches:
            m = self.add_target(em) if target else self.add_source(em)
            if m:
                return m
        return None

    def end_for_new_connection(self, target: bool, other_end: Optional[AddressMatch] = None) -> Optional[AddressMatch]:
        """Pick best source or target for new connection"""
        end = None
        for ms in (self.targets if target else self.sources).values():
            if other_end and ms.endpoint.is_same_host(other_end.endpoint):
                continue
            if not ms.endpoint.new_connections():
                continue
            if ms.endpoint.match_priority > 1000:
                end = ms  # cannot find better than priority one
                break
            if end and ms.endpoint.entity.match_priority > end.endpoint.entity.match_priority:
                end = ms
                continue
            end = end or ms  # pick first host
        return end


class MatchEngine:
    """Match engine, can have engines for different sources"""
    def __init__(self, system: SystemMatcher, source: EvidenceSource):
        self.system = system
        self.endpoints: Dict[AddressAtNetwork, List[MatchEndpoint]] = {}
        self.observed: Dict[Flow, ConnectionMatch] = {}
        self.source = source if isinstance(source, EvidenceNetworkSource) else None
        for h in system.system.get_hosts():
            self._add_host(h)
        if self.source:
            # load source-specific stuff
            for ad, ent in self.source.address_map.items():
                ad_networks = ent.get_networks_for(ad)
                # add entity for corrent network(s)
                for nw in ad_networks:
                    ex_ent = self.endpoints.setdefault(AddressAtNetwork(ad, nw), [])
                    for ex in ex_ent:
                        if ex.entity == ent:
                            ex.add_address(ad)  # entity has new address
                            break
                    else:
                        # no other addresses, but source-specific one
                        ex_ent.append(self._add_host(ent).add_address(ad))
            for me in itertools.chain(*self.endpoints.values()):
                # check if exteranal activity changes for some entities
                fs = self.source.activity_map.get(me.entity)
                if fs is not None:
                    me.external_activity = fs

    def update_addresses(self, host: Host, old: Set[AnyAddress]):
        """Update addresses for a host"""
        # remove old mappings for the addresses
        for ad in old:
            ad_networks = host.get_networks_for(ad)
            for nw in ad_networks:
                key = AddressAtNetwork(ad, nw)
                ends = self.endpoints.get(key, [])
                self.endpoints[key] = [m for m in ends if m.entity != host]
        # add the host again
        self._add_host(host)

    def _add_host(self, entity: Addressable) -> 'MatchEndpoint':
        if entity.any_host:
            ads = []  # always match by wildcards
        else:
            ads = {a.get_host(): None for a in entity.get_addresses() if not a.is_tag()}.keys()

        if ads:
            # addressed host
            me = MatchEndpoint(entity, priority_services=True)
            for ad in ads:
                # match service, may fallback to host and create unexpected services
                ad_networks = entity.get_networks_for(ad)
                for nw in ad_networks:
                    self.endpoints.setdefault(AddressAtNetwork(ad, nw), []).append(me)
        else:
            # no addresses, but services -> match any with service ports
            # no addresses and no services -> match any flow
            me = MatchEndpoint(entity, match_no_service=not entity.children)
            for nw in entity.get_networks():
                self.endpoints.setdefault(AddressAtNetwork(Addresses.ANY, nw), []).append(me)
        return me

    def get_connection(self, flow: Flow) -> ConnectionMatch:
        """Find the connection matching the given flow, return also endpoint addresses"""
        system = self.system.system
        m = self.get_observed(flow)
        if m:
            # the flow or it's reverse already seen
            if m.reply:
                system.connections[m.target.address, m.source.address] = m.connection
            target_h = m.connection.target
            if not m.reply or not isinstance(target_h, Host):
                return m  # ...nothing new here
            # reply, there is an unexpected service replying -> create an unexpected service
            self.create_unknown_service(m)
        else:
            # new flow, may be existing or new source and/or target
            m = self.add_connection(flow)
            if m.connection.status == Status.PLACEHOLDER:
                # this is an UNEXPECTED connection found after reset
                self.set_connection_status(m.connection, m.source, m.target)
            self.observed[flow] = m
        conn = m.connection
        conn.source.new_connection(conn, flow, target=m.reply)
        conn.target.new_connection(conn, flow, target=not m.reply)
        system.connections[m.source.address, m.target.address] = conn
        return m

    def get_observed(self, flow: Flow) -> Optional[ConnectionMatch]:
        """Get cached observed connection match, if there is one"""
        c = self.observed.get(flow)
        if c:
            return c
        # check the other way
        r = flow.reverse()
        c = self.observed.get(r)
        if c:
            # reverse direction
            if c.connection.status == Status.EXTERNAL:
                # connection from source to target was ok, but target is now replying
                te = c.target.endpoint
                if te.entity.status != Status.EXTERNAL and \
                        te.entity.external_activity < ExternalActivity.OPEN:
                    # target should not reply
                    c.connection.set_property(Properties.EXPECTED.verdict(Verdict.FAIL))

            rc = ConnectionMatch(c.connection, c.source, c.target, reply=True)
            self.observed[flow] = rc
            return rc
        return None

    def create_unknown_service(self, match: ConnectionMatch):
        """Create an unknown service due observing reply from it"""
        system = self.system.system
        conn = match.connection
        target_h = conn.target
        assert isinstance(target_h, Host)
        n_service_ep = match.target.address
        assert conn not in target_h.connections, "Connection already added to target host"
        assert isinstance(n_service_ep, EndpointAddress), "Expected endpoint address from observation cache"
        # change connection to point the new service
        n_service = target_h.create_service(n_service_ep)
        if target_h.external_activity >= ExternalActivity.UNLIMITED and conn.status == Status.EXTERNAL:
            # host is free to provide unlisted services
            n_service.status = Status.EXTERNAL
        target_h.connections.append(conn)
        networks = target_h.get_networks_for(n_service_ep.get_host())
        for nw in networks:
            # for each network, the host is in
            for ep in self.endpoints[AddressAtNetwork(n_service_ep.get_host(), nw)]:
                if ep.entity == target_h:
                    ep.add_service(n_service)
        conn.target = n_service
        # create new connection for connections from same the source to the same target host, but different port
        new_c = None
        new_obs: Dict[Flow, ConnectionMatch] = {}
        for of, om in self.observed.items():
            if om.connection == conn and om.target.address != n_service_ep:
                # same connection, but different target address
                if new_c is None:
                    new_c = system.new_connection((conn.source, om.source.address), (target_h, om.target.address))
                    self.set_connection_status(new_c, om.source, om.target)
                else:
                    system.connections[om.source.address, om.target.address] = new_c
                new_m = ConnectionMatch(new_c, om.source, om.target, om.reply)
                new_obs[of] = new_m
        self.observed.update(new_obs)

    def add_connection(self, flow: Flow) -> ConnectionMatch:
        """Add new connection"""
        # find expected connections, collect endpoints in priority order while at it
        finder = ConnectionFinder(self.system, unexpected=False)
        m = self.find_connection(finder, flow)
        if m:
            return m

        # pick the best target for unexpected connection
        tar = finder.end_for_new_connection(target=True)
        if tar and tar.endpoint.entity.is_host():
            # check if a reverse direction connection, perhaps we missed earlier request or unexpected DHCP
            m = tar.endpoint.match_connection(tar, finder.sources.values(), unexpected=False)
            if m:
                m.reply = True
                return m

        # pick best source for the unexpected connection
        src = finder.end_for_new_connection(target=False, other_end=tar)

        if src and tar:
            # is there already an existing, but unexpected, connection?
            f2 = ConnectionFinder(self.system, unexpected=True)
            f2.add_source(src)
            m = f2.add_target(tar)
            if m:
                return m

        # create new source, target and connection (as required)
        src = src or self.new_endpoint(flow, target=False)
        tar = tar or self.new_endpoint(flow, target=True)
        return self.new_connection(src, tar)

    def find_connection(self, finder: ConnectionFinder, flow: Flow) -> Optional[ConnectionMatch]:
        """Match endpoints by given criteria"""
        match_address = {
            False: self._match_addresses(flow, target=False),
            True: self._match_addresses(flow, target=True)}

        # 1. match host address + service
        for target, match_ads in match_address.items():
            for ad in match_ads:
                ends = self.endpoints.get(ad, [])
                for end in ends:
                    am = end.match_service(ad.address, flow, target)
                    m = finder.add_matches(am, target)
                    if m:
                        return m

        # 2. match hosts by address
        for target, match_ads in match_address.items():
            for ad in match_ads:
                ends = self.endpoints.get(ad, [])
                for end in ends:
                    if end.match_no_service:
                        am = AddressMatch(EndpointAddress(ad.address, flow.protocol, flow.port(target)), end)
                        m = finder.add_matches([am], target)
                        if m:
                            return m

        # 3. match <any address> + service
        wild_ends = self.endpoints.get(
            AddressAtNetwork(Addresses.ANY, flow.network or self.system.system.get_default_network()), [])
        for target, match_ads in match_address.items():
            for end in wild_ends:
                for ad in match_ads:
                    am = end.match_service(ad.address, flow, target)
                    m = finder.add_matches(am, target)
                    if m:
                        return m

        # 4. match hosts with wildcard address
        for target, match_ads in match_address.items():
            for end in wild_ends:
                if end.match_no_service:
                    for ad in match_ads:
                        am = AddressMatch(EndpointAddress(ad.address, flow.protocol, flow.port(target)), end)
                        m = finder.add_matches([am], target)
                        if m:
                            return m
        return None

    def _match_addresses(self, flow: Flow, target: bool) -> Tuple[AddressAtNetwork, ...]:
        """Resolve matching addresses for a flow"""

        net = flow.network or self.system.system.get_default_network()

        if isinstance(flow, IPFlow):
            end = flow.target if target else flow.source
            if self.system.system.is_external(end[1]):
                return (AddressAtNetwork(end[1], net), )  # match by IP only (HW for gateway)
            return tuple(AddressAtNetwork(e, net) for e in end[0:2]) # HW and IP

        return tuple(AddressAtNetwork(e, net) for e in flow.stack(target))

    def new_endpoint(self, flow: Flow, target: bool) -> 'AddressMatch':
        """Create a new endpoint host"""
        system = self.system.system
        stack = flow.stack(target)
        use_ad = stack[0]
        for ad in stack[1:]:
            if isinstance(ad, IPAddress) and (system.is_external(ad) or ad.is_multicast()):
                use_ad = ad  # must use the IP address
                break
            if use_ad.is_null() and not ad.is_null():
                use_ad = ad  # prefer non-null address
        host = system.get_endpoint(use_ad, at_network=flow.network)
        # target address with port
        ad = EndpointAddress(use_ad, flow.protocol, flow.port(target))
        return AddressMatch(ad, self._add_host(host))

    def new_connection(self, source: AddressMatch, target: AddressMatch) -> ConnectionMatch:
        """New connection, unexpected"""
        system = self.system.system
        sad = source.endpoint.entity, source.address
        tad = target.endpoint.entity, target.address
        c = system.new_connection(sad, tad)
        self.set_connection_status(c, source, target)
        return ConnectionMatch(c, source, target)

    def set_connection_status(self, connection: Connection,
                              source: 'AddressMatch', target: 'AddressMatch') -> Connection:
        """Set status for unexpected connection"""
        c = connection
        c.status = Status.UNEXPECTED

        def set_external(e: Addressable):
            if e.status == Status.UNEXPECTED and e.get_expected_verdict() == Verdict.INCON:
                # entity is fresh and unexpected, make it external
                e.status = Status.EXTERNAL
                if isinstance(e.parent, Addressable):
                    set_external(e.parent)

        # new connection status by external activity policies and reply status
        source_act = source.endpoint.external_activity
        target_act = target.endpoint.external_activity
        if source_act > ExternalActivity.BANNED and target_act > ExternalActivity.BANNED:
            # unexpected connections may be allowed
            reply = c.source == target.endpoint.entity
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

    def __repr__(self):
        s = []
        for a, es in self.endpoints.items():
            s.append(f"{a} = " + " ".join([e.entity.name for e in es]))
        return "\n".join(s)


class MatchEndpoint:
    """Match endpoint"""
    def __init__(self, entity: Addressable, match_no_service=True, priority_services=False):
        self.entity = entity
        self.addresses = set(a for a in entity.addresses if not a.is_tag())
        self.match_no_service = match_no_service    # match without service?
        self.match_priority = entity.match_priority
        self.system = entity.get_system()
        self.services: Dict[EndpointAddress, List[MatchEndpoint]] = {}
        for s in entity.children:
            assert isinstance(s, Service), f"Non-service {s}"
            self.add_service(s, priority_services)
        self.external_activity = entity.external_activity

    def add_address(self, address: AnyAddress) -> Self:
        """Add mapped address to endpoint"""
        if not address.is_tag():
            self.addresses.add(address)
        return self

    def is_same_host(self, other: Optional['MatchEndpoint']) -> bool:
        """Does the an other endpoint have the same host"""
        return other and other.entity.get_parent_host() == self.entity.get_parent_host()

    def new_connections(self) -> bool:
        """Allow new connections with this endpoint"""
        return len(self.addresses) > 0  # 'any' host only for existing connections

    def add_service(self, service: Service, priority_services=True):
        """Add service matching to endpoint"""
        for a in service.addresses:
            assert isinstance(a, EndpointAddress), f"Non-endpoint address {a}"
            me = MatchEndpoint(service, match_no_service=False)
            if priority_services:
                me.match_priority = 1001  # the MAX
            self.services.setdefault(a, []).append(me)

    def match_service(self, address: AnyAddress, flow: Flow, target: bool) -> List[AddressMatch]:
        """Match service by address and flow"""
        m_list = []
        port = flow.port(target)
        # seek for service, exact address or just port
        ad = EndpointAddress(address, flow.protocol, port)
        for me in self.services.get(ad, []):
            m_list.append(AddressMatch(ad, me))
        wad = EndpointAddress.any(flow.protocol, port)
        for me in self.services.get(wad, []):
            m_list.append(AddressMatch(ad, me))
        return m_list

    def match_connection(self, source: AddressMatch, ends: Iterable[AddressMatch],
                         unexpected=True) -> Optional[ConnectionMatch]:
        """Match connection originating from this end"""
        host = self.entity.get_parent_host()
        for c in host.connections:
            if not c.is_end(self.entity):
                continue
            if not unexpected and not c.is_expected():
                # NOTE: A hack to match unexpected DHCP reply
                target = c.target
                if not isinstance(target, Service) or not target.reply_from_other_address:
                    continue
            for end in ends:
                if self.is_same_host(end.endpoint) or not c.is_end(end.endpoint.entity):
                    continue
                # connection from this host or service
                reply = self.entity == c.target
                return ConnectionMatch(c, source, end, reply)

    def __repr__(self):
        s = [('Host ' if self.entity.is_host() else 'Service ') + f"{self.entity.name}"]
        for a, es in self.services.items():
            s.append(f"{a} = " + " ".join([e.entity.name for e in es]))
        return "\n".join(s)
