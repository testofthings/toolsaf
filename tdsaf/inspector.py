"""Model inspector"""

import logging
from typing import Dict, Optional, Set

from tdsaf.address import AnyAddress
from tdsaf.basics import ExternalActivity, Status
from tdsaf.entity import Entity
from tdsaf.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from tdsaf.matcher import SystemMatcher
from tdsaf.model import IoTSystem, Connection, Service, Host, Addressable
from tdsaf.property import Properties
from tdsaf.services import NameEvent
from tdsaf.traffic import ServiceScan, HostScan, Flow, IPFlow
from tdsaf.verdict import Verdict


class Inspector(EventInterface):
    """Inspector"""
    def __init__(self, system: IoTSystem):
        self.matcher = SystemMatcher(system)
        self.system = system
        self.logger = logging.getLogger("inspector")
        self.connection_count: Dict[Connection, int] = {}  # count connections
        self.direction: Dict[Flow, bool] = {}              # direction: false = request, true = reply
        self.known_entities: Set[Entity] = set()            # known entities
        self._list_hosts()

    def reset(self):
        """Reset the system clearing all evidence"""
        self.matcher.reset()
        self.connection_count.clear()
        self.direction.clear()
        self._list_hosts()

    def _list_hosts(self):
        """List all hosts"""
        self.known_entities.clear()
        self.known_entities.update(self.system.iterate_all())

    def _check_entity(self, entity: Entity) -> bool:
        """Check if an entity is known, send events, as required"""
        if entity in self.known_entities:
            return False
        self.known_entities.add(entity)
        # new entity, send event
        if isinstance(entity, Connection):
            self.system.call_listeners(lambda ln: ln.connection_change(entity))
        if isinstance(entity, Host):
            self.system.call_listeners(lambda ln: ln.host_change(entity))
        if isinstance(entity, Service):
            self.system.call_listeners(lambda ln: ln.service_change(entity))
        return True

    def get_system(self) -> IoTSystem:
        return self.system

    def connection(self, flow: Flow) -> Optional[Connection]:
        self.logger.debug("inspect flow %s", flow)
        key = self.matcher.connection_w_ends(flow)
        conn, _, _, reply = key
        assert conn.status != Status.PLACEHOLDER, f"Received placeholder connection: {conn}"

        flow.reply = reply  # bit ugly to fix, but now available for logger

        conn_c = self.connection_count.get(conn, 0) + 1
        self.connection_count[conn] = conn_c
        new_conn = conn_c == 1  # new connection?

        # detect new sessions
        conn_dir = self.direction.get(flow)
        new_direction = conn_dir is None  # new direction?
        if new_direction:
            self.direction[flow] = not reply

        if not (new_conn or new_direction):
            return None  # old connection, old direction -> discard

        updated = set()   # entity which status updated
        send = set()      # force to send entity update

        def update_seen_status(entity: Addressable):
            changed = []
            entity.set_seen_now(changed)
            updated.update(changed)

        # if we have a connection, the endpoints cannot be placeholders
        source, target = conn.source, conn.target
        if source.status == Status.PLACEHOLDER:
            source.status = conn.status
        if target.status == Status.PLACEHOLDER:
            target.status = conn.status

        if new_conn:
            # new connection is observed
            conn.set_seen_now()
            updated.add(conn)
            # what about learning local IP/HW address pairs
            if isinstance(flow, IPFlow):
                ends = (conn.target, conn.source) if reply else (conn.source, conn.target)
                learn = ends[0].get_parent_host().learn_address_pair(flow.source[0], flow.source[1])
                if learn:
                    send.add(ends[0])
                learn = ends[1].get_parent_host().learn_address_pair(flow.target[0], flow.target[1])
                if learn:
                    send.add(ends[1])

        if new_direction:
            # new direction, may be old connection
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
                        target.set_property(Properties.EXPECTED.verdict(Verdict.INCON))
            else:
                # a reply
                update_seen_status(target)

        # these entities to send events, in this order
        entities = [conn, source, source.get_parent_host(), target, target.get_parent_host()]
        for ent in entities:
            is_new = self._check_entity(ent)
            if is_new:
                updated.discard(ent)  # no separate update required

        # flow event can carry properties
        if conn.status == Status.EXPECTED:
            for p, v in flow.properties.items():
                # No model events, perhaps later?
                p.update(conn.properties, v)
                self.system.call_listeners(
                    lambda ln: ln.property_change(conn, (p, v)))  # pylint: disable=cell-var-from-loop

        for ent in entities:
            if ent not in updated:
                continue
            ev = Properties.EXPECTED.verdict(ent.get_expected_verdict())
            self.system.call_listeners(lambda ln: ln.property_change(ent, ev))  # pylint: disable=cell-var-from-loop
            updated.discard(ent)
        return conn

    def name(self, event: NameEvent) -> Optional[Host]:
        address = event.address
        if event.service and event.service.captive_portal and event.address in event.service.parent.addresses:
            address = None  # it is just redirecting to itself
        name = event.tag or event.name
        h, changes = self.system.learn_named_address(name, address)
        if h not in self.known_entities:
            # new host
            if h.status == Status.UNEXPECTED:
                # unexpected host, check if it can be external
                for pe in event.peers:
                    if name in pe.get_parent_host().ignore_name_requests:
                        # this name is explicitly ok
                        continue
                    if pe.external_activity < ExternalActivity.OPEN:
                        # should not ask or reply with unknown names
                        h.set_seen_now()
                        break
                else:
                    # either unknown DNS requester or peers can be externally active
                    h.status = Status.EXTERNAL
            self.known_entities.add(h)
        elif not changes:
            # old host and nothing learned -> stop this maddness to save resources
            return None
        self.system.call_listeners(lambda ln: ln.address_change(h))
        return h

    def property_update(self, update: PropertyEvent) -> Entity:
        s = update.entity
        if s.status in {Status.PLACEHOLDER, Status.UNEXPECTED}:
            # no properties for placeholders or unexpected entities
            return s
        key, val = update.key_value
        if key.model and key not in s.properties:
            self.logger.debug("Value for model property %s ignored, as it is not in model", key)
            return None
        key.update(s.properties, val)
        # call listeners
        self.system.call_listeners(lambda ln: ln.property_change(s, (key, val)))
        return s

    def property_address_update(self, update: PropertyAddressEvent) -> Entity:
        add = update.address
        s = self._get_seen_entity(add)
        if s is None:
            raise NotImplementedError(f"Processing properties for {add} not implemented")
        if s.status in {Status.PLACEHOLDER, Status.UNEXPECTED}:
            # no properties for placeholders or unexpected entities
            return s
        key, val = update.key_value
        if key.model and key not in s.properties:
            self.logger.debug("Value for model property %s ignored, as it is not in model", key)
            return s
        key.update(s.properties, val)
        # call listeners
        self.system.call_listeners(lambda ln: ln.property_change(s, (key, val)))
        return s

    def service_scan(self, scan: ServiceScan) -> Service:
        """The given address has a service"""
        s = self._get_seen_entity(scan.endpoint)
        assert isinstance(s, Service)
        host = s.get_parent_host()
        new_host = self._check_entity(host)
        if not new_host:
            # known host, but what about the service
            self._check_entity(s)
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
                c.set_property(Properties.EXPECTED.verdict(Verdict.FAIL))
        self.known_entities.add(host)
        self.system.call_listeners(lambda ln: ln.host_change(host))
        return host

    def _get_seen_entity(self, endpoint: AnyAddress) -> Addressable:
        """Get entity by address, mark it seen"""
        ent = self.system.get_endpoint(endpoint)
        change = ent.set_seen_now()
        if change and ent.status == Status.EXPECTED:
            value = Properties.EXPECTED, Properties.EXPECTED.get(ent.properties)
            self.system.call_listeners(lambda ln: ln.property_change(ent, value))
        return ent

    def __repr__(self):
        return self.system.__repr__()
