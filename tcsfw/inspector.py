import datetime
import logging
from typing import Dict, Tuple

from tcsfw.address import DNSName, AnyAddress
from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from tcsfw.matcher import SystemMatcher
from tcsfw.model import IoTSystem, Connection, Service, Host, Addressable, NodeComponent
from tcsfw.property import Properties
from tcsfw.services import NameEvent
from tcsfw.traffic import ServiceScan, HostScan, Flow, IPFlow
from tcsfw.verdict import Status, Verdict


class Inspector(EventInterface):
    """Inspector"""
    def __init__(self, system: IoTSystem):
        self.matcher = SystemMatcher(system)
        self.system = system
        self.logger = logging.getLogger("inspector")
        self.connection_count: Dict[Connection, int] = {}
        self.sessions: Dict[Flow, bool] = {}
        self.dns_names: Dict[str, Host] = {}

    def reset(self):
        """Reset the system clearing all evidence"""
        self.matcher.reset()
        self.connection_count.clear()
        self.sessions.clear()
        self.dns_names.clear()
        # Ask clients to reload NOW - hosts and connection are not sent
        self.system.call_listeners(lambda ln: ln.systemReset(self.system))

    def get_system(self) -> IoTSystem:
        return self.system

    def connection(self, flow: Flow) -> Connection:
        self.logger.debug("inspect flow %s", flow)
        key = self.matcher.connection_w_ends(flow)
        conn, s, t, reply = key

        flow.reply = reply  # bit ugly to fix, but now available for logger

        assert conn.status != Status.PLACEHOLDER, f"Received placeholder connection: {conn}"

        c_count = self.connection_count.get(conn, 0) + 1
        self.connection_count[conn] = c_count

        # detect new sessions
        session = self.sessions.get(flow)
        new_session = session is None
        if new_session:
            # new session or direction
            self.sessions[flow] = reply

        send = set()  # connection, flow, source and/or target

        def update_seen_status(entity: Addressable):
            mod_s = entity.set_seen_now()
            if mod_s is not None:
                send.add(entity)  # verdict change, must send the entity

        # if we have a connection, the endpoints cannot be placeholders
        source, target = conn.source, conn.target
        if source.status == Status.PLACEHOLDER:
            source.status = conn.status
        if target.status == Status.PLACEHOLDER:
            target.status = conn.status

        external = conn.status == Status.EXTERNAL
        if c_count == 1:
            # new connection is seen
            conn.set_seen_now()
            send.add(conn)
            # what about learning local IP/HW address pairs
            if isinstance(flow, IPFlow):
                ends = (conn.target, conn.source) if reply else (conn.source, conn.target)
                learn = ends[0].get_parent_host().learn_address_pair(flow.source[0], flow.source[1])
                if learn:
                    send.add(ends[0])
                learn = ends[1].get_parent_host().learn_address_pair(flow.target[0], flow.target[1])
                if learn:
                    send.add(ends[1])

        if new_session:
            # flow event for each new session
            send.add(flow)
            # new direction, update sender
            if not reply:
                update_seen_status(source)
                if target.status == Status.UNEXPECTED:
                    # unexpected target fails instantly
                    update_seen_status(target)
                elif conn.target.is_relevant() and conn.target.is_multicast():
                    # multicast updated when sent to
                    update_seen_status(target)
                elif target.status == Status.EXTERNAL:
                    # external target, send update even that verdict remains inconclusve
                    exp = conn.target.get_expected_verdict(default=None)
                    if exp is None:
                        target.set_property(Properties.EXPECTED.value(Verdict.INCON))
                        send.add(target)
            else:
                # a reply
                update_seen_status(target)

        if self.system.model_listeners and send:
            if source in send:
                self.system.call_listeners(lambda ln: ln.hostChange(source.get_parent_host()))
            if target in send:
                self.system.call_listeners(lambda ln: ln.hostChange(target.get_parent_host()))
            if conn in send:
                self.system.call_listeners(lambda ln: ln.connectionChange(conn))
            if flow in send:
                self.system.call_listeners(lambda ln: ln.newFlow(s, t, flow, conn))
        return conn

    def name(self, event: NameEvent) -> Host:
        address = event.address
        if event.service and event.service.captive_portal and event.address in event.service.parent.addresses:
            address = None  # it is just redirecting to itself
        h = self.system.learn_named_address(DNSName(event.name), address)
        self.system.call_listeners(lambda ln: ln.hostChange(h))
        if event.address:
            self.dns_names[event.name] = h
            # FIXME: This should be a claim and verification!
            # s_host = event.service.get_parent_host()
            # to_self = 0
            # for s in self.dns_names.values():
            #     to_self += 1 if s == s_host else 0
            # self.logger.info("%s self-responses=%d/%d", event.service.long_name(), to_self, len(self.dns_names))
            # if to_self > 1 and to_self > len(self.dns_names) * .5:
            #     pass
        return h

    def property_update(self, update: PropertyEvent) -> Entity:
        s = update.entity
        key, val = update.key_value
        if key.model and key not in s.properties:
            self.logger.debug("Value for model property %s ignored, as it is not in model", key)
            return None
        key.update(s.properties, val)
        if isinstance(s, Addressable):
            self.system.call_listeners(lambda ln: ln.hostChange(s.get_parent_host()))
            return s
        if isinstance(s, NodeComponent):
            self.system.call_listeners(lambda ln: ln.hostChange(s.entity.get_parent_host()))
            return s
        if isinstance(s, Connection):
            self.system.call_listeners(lambda ln: ln.connectionChange(s))
            return s
        if isinstance(s, IoTSystem):
            return s  # No event - not shown in GUI now
        raise NotImplementedError(f"Processing properties for {s} not implemented")

    def property_address_update(self, update: PropertyAddressEvent) -> Entity:
        add = update.address
        s = self._get_seen_entity(add)
        if s is None:
            raise NotImplementedError(f"Processing properties for {add} not implemented")
        key, val = update.key_value
        if key.model and key not in s.properties:
            self.logger.debug("Value for model property %s ignored, as it is not in model", key)
            return s
        key.update(s.properties, val)
        self.system.call_listeners(lambda ln: ln.hostChange(s.get_parent_host()))
        return s

    def service_scan(self, scan: ServiceScan) -> Service:
        """The given address has a service"""
        s = self._get_seen_entity(scan.endpoint)
        assert isinstance(s, Service)
        self.system.call_listeners(lambda ln: ln.hostChange(s.get_parent_host()))
        return s

    def host_scan(self, scan: HostScan) -> Host:
        host = self.system.get_endpoint(scan.host)
        assert isinstance(host, Host), f"Address {scan.host} is not for a Host"
        for c in host.children:
            if isinstance(c, Service):
                if c.client_side or not c.is_tcp_service():
                    continue  # only server TCP services are scannable
            if not c.is_relevant():
                continue  # verdict does not need checking
            for a in c.addresses:
                if a in scan.endpoints:
                    break
                if a.is_wildcard() and a.change_host(scan.host) in scan.endpoints:
                    break
            else:
                # child address not in scan results
                c.set_property(Properties.EXPECTED.value(Verdict.FAIL))
        self.system.call_listeners(lambda ln: ln.hostChange(host))
        return host

    def _get_seen_entity(self, endpoint: AnyAddress) -> Addressable:
        """Get entity by address, mark it seen"""
        ent = self.system.get_endpoint(endpoint)
        ent.set_seen_now()
        return ent

    def __repr__(self):
        return self.system.__repr__()
