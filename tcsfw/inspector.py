import datetime
import logging
from typing import Dict, Tuple

from tcsfw.address import DNSName, AnyAddress
from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from tcsfw.matcher import SystemMatcher
from tcsfw.model import IoTSystem, Connection, Service, Host, Session, Addressable, NodeComponent
from tcsfw.services import NameEvent
from tcsfw.traffic import ServiceScan, HostScan, Flow, IPFlow
from tcsfw.verdict import Verdict, VerdictEvent, FlowEvent


class Inspector(EventInterface):
    """Inspector"""
    def __init__(self, system: IoTSystem):
        self.matcher = SystemMatcher(system)
        self.system = system
        self.logger = logging.getLogger("inspector")
        self.connection_count: Dict[Connection, int] = {}
        self.sessions: Dict[Flow, Tuple[Session, bool]] = {}
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

        assert conn.status.verdict != Verdict.UNDEFINED, f"Received connection with verdict undefined: {conn}"
        # Note: hosts and services _can_ be Undefined???

        c_count = self.connection_count.get(conn, 0) + 1
        self.connection_count[conn] = c_count

        # FIXME: Shouldn't model add sessions, why inspector?
        session, _ = self.sessions.get(flow, (None, None))
        new_session = not session
        if new_session:
            session, _ = self.sessions.get(flow.reverse(), (None, None))
            if not session:
                # truly new session
                session = Session(flow.timestamp or datetime.datetime.now())
                conn.sessions.append(session)
                self.sessions[flow] = session, reply
            else:
                # old session in reverse direction
                self.sessions[flow] = session, reply

        send = set()  # connection, flow, source and/or target

        def update_verdict(entity: Addressable, new_verdict: Verdict):
            old_v = entity.status.verdict
            new_v = entity.update_verdict(new_verdict)
            if old_v != new_v:
                send.add(entity)  # verdict change, must send the entity

        source, target = conn.source, conn.target
        external = conn.status.verdict == Verdict.EXTERNAL
        if c_count == 1:
            # new connection
            send.add(conn)
            if conn.status.verdict == Verdict.NOT_SEEN:
                # connection is seen now
                conn.status.verdict = Verdict.PASS
            elif external:
                # External connection, maybe some endpoints are too..?
                for h in [source, target]:
                    if h.status.verdict == Verdict.UNDEFINED:
                        update_verdict(h, Verdict.EXTERNAL)
                    elif h.status.verdict == Verdict.NOT_SEEN:
                        update_verdict(h, Verdict.PASS)  # well, we have seen it now - FIXME: not good?

            # what about learning local IP/HW address pairs
            if isinstance(flow, IPFlow):
                ends = (conn.target, conn.source) if reply else (conn.source, conn.target)
                learn = ends[0].get_parent_host().learn_address_pair(flow.source[0], flow.source[1])
                if learn:
                    send.add(ends[0])
                learn = ends[1].get_parent_host().learn_address_pair(flow.target[0], flow.target[1])
                if learn:
                    send.add(ends[1])

        ev = None
        if new_session:
            # Flow event for each new session
            verdict = conn.status.verdict
            assert verdict != Verdict.UNDEFINED
            ev = FlowEvent((s, t), reply, flow, verdict=verdict)
            session.status.add_result(ev)
            send.add(ev)
            # new direction, update sender
            if not reply:
                source.update_verdict(conn.status.verdict)
                send.add(source)
                if conn.target.is_relevant() and conn.target.is_multicast() and conn.target.status.is_expected():
                    # multicast updated when sent to
                    update_verdict(target, conn.status.verdict)
            elif target.is_relevant():
                update_verdict(target, conn.status.verdict)

        # if we have a connection, the endpoints cannot be undefined
        if source.status.verdict == Verdict.UNDEFINED:
            update_verdict(source, Verdict.EXTERNAL if external else Verdict.UNEXPECTED)
        if target.status.verdict == Verdict.UNDEFINED:
            update_verdict(target, Verdict.EXTERNAL if external else Verdict.UNEXPECTED)

        if self.system.model_listeners and send:
            if source in send:
                self.system.call_listeners(lambda ln: ln.hostChange(source.get_parent_host()))
            if target in send:
                self.system.call_listeners(lambda ln: ln.hostChange(target.get_parent_host()))
            if conn in send:
                self.system.call_listeners(lambda ln: ln.connectionChange(conn))
            if ev in send:
                self.system.call_listeners(lambda ln: ln.newFlow(ev, conn))
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
            return e
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
        s.status.add_result(VerdictEvent(scan, s.status.verdict))
        self.system.call_listeners(lambda ln: ln.hostChange(s.get_parent_host()))
        return s

    def host_scan(self, scan: HostScan) -> Host:
        host = self.system.get_endpoint(scan.host)
        assert isinstance(host, Host), f"Address {scan.host} is not for a Host"
        for c in host.children:
            if isinstance(c, Service):
                if c.client_side or not c.is_tcp_service():
                    continue  # only server TCP services are scannable
            if c.status.verdict not in {Verdict.NOT_SEEN, Verdict.PASS}:
                continue  # verdict does not need checking
            for a in c.addresses:
                if a in scan.endpoints:
                    break
                if a.is_wildcard() and a.change_host(scan.host) in scan.endpoints:
                    break
            else:
                # child address not in scan results
                c.update_verdict(Verdict.MISSING)
                c.status.add_result(VerdictEvent(scan, c.status.verdict))
        self.system.call_listeners(lambda ln: ln.hostChange(host))
        return host

    # FIXME: Move to Claim!
    # def release_info(self, info: ReleaseInfo) -> Optional[Software]:
    #     sw = Software.get_software(self.system, info.sw_name)
    #     if sw:
    #         sw.info = info  # just take the latest data
    #
    #         claims = Claim.identifier_map(sw.claims)
    #         first_release = FirstRelease.find(claims)
    #         release_interval = ReleaseInterval.find(claims)
    #         support_end = EndOfSupport.find(claims)
    #
    #         if release_interval is not None and info.interval_days is not None:
    #             v = Verdict.FAIL if release_interval.days > info.interval_days else Verdict.PASS
    #             sw.claims[release_interval] = ClaimStatus(
    #                 release_interval, verdict=v, explanation=f"{info.interval_days} <= {release_interval.days} days")
    #             sw.status.verdict = resolve_verdict([sw.status.verdict, v])
    #             sw.status.add_result(VerdictEvent(info, v))
    #     else:
    #         self.logger.warning("Info for unknown SW %s", info.sw_name)
    #     entity = sw.entity
    #     if isinstance(entity, Addressable):
    #         self.system.call_listeners(lambda ln: ln.hostChange(entity.get_parent_host()))
    #     return sw

    def _get_seen_entity(self, endpoint: AnyAddress) -> Addressable:
        ent = self.system.get_endpoint(endpoint)
        if ent.status.verdict == Verdict.NOT_SEEN:
            ent.update_verdict(Verdict.PASS)
        if ent.status.verdict == Verdict.UNDEFINED:
            ent.update_verdict(Verdict.UNEXPECTED)
        return ent

    def __repr__(self):
        return self.system.__repr__()
