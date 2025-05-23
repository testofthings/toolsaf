"""Model inspector"""

import logging
from typing import Dict, Optional, Set, List

from toolsaf.common.address import Addresses, AnyAddress
from toolsaf.common.basics import ExternalActivity, Status
from toolsaf.common.entity import Entity
from toolsaf.core.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from toolsaf.core.matcher import SystemMatcher
from toolsaf.core.model import IoTSystem, Connection, Service, Host, Addressable
from toolsaf.core.ignore_rules import IgnoreRules
from toolsaf.common.property import Properties
from toolsaf.core.services import NameEvent
from toolsaf.common.traffic import EvidenceSource, ServiceScan, HostScan, Flow
from toolsaf.common.verdict import Verdict


class Inspector(EventInterface):
    """Inspector"""
    def __init__(self, system: IoTSystem, ignore_rules: Optional[IgnoreRules]=None) -> None:
        super().__init__()
        self.matcher = SystemMatcher(system)
        self.system = system
        self.ignore_rules = ignore_rules if ignore_rules else IgnoreRules()
        self.logger = logging.getLogger("inspector")
        self.connection_count: Dict[Connection, int] = {}  # count connections
        self.direction: Dict[Flow, bool] = {}              # direction: false = request, true = reply
        self.known_entities: Set[Entity] = set()            # known entities
        self._list_hosts()

    def reset(self) -> None:
        """Reset the system clearing all evidence"""
        self.matcher.reset()
        self.connection_count.clear()
        self.direction.clear()
        self._list_hosts()

    def _list_hosts(self) -> None:
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

        def update_seen_status(entity: Addressable) -> bool:
            """Update seen status of entity"""
            changed: List[Entity] = []
            change = entity.set_seen_now(changed)
            updated.update(changed)
            return change

        def update_all_broadcast_listeners(target: Addressable) -> bool:
            """Matcher only finds one broadcast listener, update the remaining"""
            if not update_seen_status(target):
                return False
            mc = Addresses.get_multicast(target.addresses)
            if not mc:
                return True
            for c in self.system.get_connections():
                if mc in c.target.addresses:
                    # same target address -> same broadcast
                    change = c.set_seen_now()
                    if change:
                        self._check_entity(c)
                        updated.add(c)
                    change = c.target.set_seen_now()
                    if change:
                        self._check_entity(c.target)
                        updated.add(c.target)
            return True


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
            # - stopped learning, makes order of input important, not good

        if new_direction:
            # new direction, may be old connection
            if not reply:
                update_seen_status(source)
                if target.status == Status.UNEXPECTED:
                    # unexpected target fails instantly
                    update_seen_status(target)
                elif conn.target.is_relevant() and conn.target.is_multicast():
                    # multicast updated when sent to
                    update_all_broadcast_listeners(target)
                elif target.status == Status.EXTERNAL:
                    # external target, send update even that verdict remains inconclusve
                    exp = conn.target.get_expected_verdict(default=None)
                    if exp is None:
                        target.set_property(Properties.EXPECTED.verdict(Verdict.INCON))
            else:
                # a reply
                update_seen_status(target)

        # these entities to send events, in this order
        entities: List[Entity] = [conn, source, source.get_parent_host(), target, target.get_parent_host()]
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
            exp_ver = ent.get_expected_verdict()
            assert exp_ver, f"Entity in update list, but verdict unkonwn {ent.long_name()}"
            ev = Properties.EXPECTED.verdict(exp_ver)
            self.system.call_listeners(lambda ln: ln.property_change(ent, ev))  # pylint: disable=cell-var-from-loop
            updated.discard(ent)
        return conn

    def name(self, event: NameEvent) -> Optional[Host]:
        address = event.address
        if event.service and event.service.captive_portal \
                and event.address in event.service.get_parent_host().addresses:
            address = None  # it is just redirecting to itself
        name = event.tag or event.name
        assert name, "Name event without tag or name"
        h, changes = self.system.learn_named_address(name, address)
        if h is not None and h not in self.known_entities:
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
        if h:
            self.system.call_listeners(lambda ln: ln.address_change(h))
        return h

    def property_update(self, update: PropertyEvent) -> Optional[Entity]:
        s = update.entity
        if s.status in {Status.PLACEHOLDER, Status.UNEXPECTED}:
            # no properties for placeholders or unexpected entities
            return s
        key, val = update.key_value
        if key.model and key not in s.properties:
            self.logger.debug("Value for model property %s ignored, as it is not in model", key)
            return None
        val = self.ignore_rules.update_based_on_rules(update.evidence.source.label, key, val, s)
        key.update(s.properties, val)
        # call listeners
        self.system.call_listeners(lambda ln: ln.property_change(s, (key, val)))
        return s

    def property_address_update(self, update: PropertyAddressEvent) -> Entity:
        add = update.address
        s = self._get_seen_entity(add, update.evidence.source)
        if s is None:
            raise NotImplementedError(f"Processing properties for {add} not implemented")
        if s.status in {Status.PLACEHOLDER, Status.UNEXPECTED}:
            # no properties for placeholders or unexpected entities
            return s
        key, val = update.key_value
        val = self.ignore_rules.update_based_on_rules(update.evidence.source.label, key, val, s)
        if key.model and key not in s.properties:
            self.logger.debug("Value for model property %s ignored, as it is not in model", key)
            return s
        key.update(s.properties, val)
        # call listeners
        self.system.call_listeners(lambda ln: ln.property_change(s, (key, val)))
        return s

    def service_scan(self, scan: ServiceScan) -> Service:
        """The given address has a service"""
        s = self._get_seen_entity(scan.endpoint, scan.evidence.source)
        assert isinstance(s, Service)
        host = s.get_parent_host()
        new_host = self._check_entity(host)
        if not new_host:
            # known host, but what about the service
            self._check_entity(s)
        return s

    def host_scan(self, scan: HostScan) -> Host:
        host = self._get_seen_entity(scan.host, scan.evidence.source)
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

    def _get_seen_entity(self, endpoint: AnyAddress, source: EvidenceSource) -> Addressable:
        """Get entity by address, mark it seen"""
        ent = self.matcher.endpoint(endpoint, source)
        change = ent.set_seen_now()
        if change and ent.status == Status.EXPECTED:
            value = Properties.EXPECTED, Properties.EXPECTED.get(ent.properties)
            self.system.call_listeners(lambda ln: ln.property_change(ent, value))
        return ent

    def __repr__(self)-> str:
        return self.system.__repr__()
