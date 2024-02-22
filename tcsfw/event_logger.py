from logging import Logger
from typing import Any, List, Set, TextIO, Tuple, Dict, Optional, cast
from tcsfw.address import AnyAddress

from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyEvent, PropertyAddressEvent
from tcsfw.inspector import Inspector
from tcsfw.model import IoTSystem, Connection, Host, ModelListener, Service, NetworkNode
from tcsfw.property import Properties, PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import EvidenceSource, HostScan, ServiceScan, Flow, Event
from tcsfw.verdict import Status, Verdict


class LoggingEvent:
    """Event with logging"""
    def __init__(self, event: Event, entity: Optional[Entity] = None, property: Tuple[PropertyKey, Any] = None):
        self.event = event
        self.property = property  # implicit property set
        self.entity = entity
        self.verdict = Verdict.INCON

    def pick_status_verdict(self, entity: Optional[Entity]):
        """Pick current status verdict"""
        if entity is not None:
            self.entity = entity
            self.verdict = Properties.EXPECTED.get_verdict(entity.properties) or Verdict.INCON

    def get_value_string(self) -> str:
        """Get value as string"""
        v = self.event.get_value_string()
        if self.property is None:
            if self.entity:
                st = f"{self.entity.status.value}/{self.verdict.value}" if self.verdict != Verdict.INCON  \
                    else self.entity.status.value
                v += f" [{st}]" if v else st
        else:
            v += (" " if v else "") + self.property[0].get_value_string(self.property[1])
        return v

    def get_properties(self) -> Set[PropertyKey]:
        """Get implicit and explicit properties"""
        r = set()
        if self.property:
            r.add(self.property[0])
        ev = self.event
        if isinstance(ev, PropertyEvent) or isinstance(ev, PropertyAddressEvent):
            r.add(ev.key_value[0])
        return r

    def __repr__(self):
        v = ""
        if self.entity:
            v += f"{self.entity.long_name()}"
        v += f" {self.get_value_string()}"
        return v


class EventLogger(EventInterface, ModelListener):
    def __init__(self, inspector: Inspector):
        self.inspector = inspector
        self.logs: List[LoggingEvent] = []
        self.current: Optional[LoggingEvent] = None  # current event
        inspector.system.model_listeners.append(self) # subscribe property events
        self.event_logger: Optional[Logger] = None

    def print_event(self, log: LoggingEvent):
        """Print event for debugging"""
        e = log.event
        s = f"{log.entity.long_name()}," if log.entity else ""
        s = f"{s:<40}"
        s += f"{log.get_value_string()},"
        s = f"{s:<80}"
        com = e.get_comment() or e.evidence.get_reference()
        if com:
            s += f" {com}"
        self.event_logger.info(s)

    def _add(self, event: Event, entity: Optional[Entity] = None, 
             property: Tuple[PropertyKey, Any] = None) -> LoggingEvent:
        """Add new current log entry"""
        ev = LoggingEvent(event, entity, property)
        self.logs.append(ev)
        self.current = ev
        return ev

    def reset(self):
        """Reset the log"""
        self.logs.clear()
        self.inspector.reset()

    def get_system(self) -> IoTSystem:
        return self.inspector.system

    def propertyChange(self, entity: Entity, value: Tuple[PropertyKey, Any]):
        if self.current is None:
            self.logger.warning("Property change without event to assign it: %s", value[0])
        # assign all property changes during an event
        ev = LoggingEvent(self.current.event, entity=entity, property=value)
        self.logs.append(ev)
        if self.event_logger:
            self.print_event(ev)

    def connection(self, flow: Flow) -> Connection:
        lo = self._add(flow)
        e = self.inspector.connection(flow)
        lo.pick_status_verdict(e)
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def name(self, event: NameEvent) -> Host:
        lo = self._add(event)
        e = self.inspector.name(event)
        lo.pick_status_verdict(e)
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def property_update(self, update: PropertyEvent) -> Entity:
        lo = self._add(update)
        e = self.inspector.property_update(update)
        lo.entity = e
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def property_address_update(self, update: PropertyAddressEvent) -> Entity:
        lo = self._add(update)
        e = self.inspector.property_address_update(update)
        lo.entity = e
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def service_scan(self, scan: ServiceScan) -> Service:
        lo = self._add(scan)
        e = self.inspector.service_scan(scan)
        lo.pick_status_verdict(e)
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def host_scan(self, scan: HostScan) -> Host:
        lo = self._add(scan)
        e = self.inspector.host_scan(scan)
        lo.pick_status_verdict(e)
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def collect_flows(self) -> Dict[Connection, List[Tuple[AnyAddress, AnyAddress, Flow]]]:
        """Collect relevant connection flows"""
        r = {}
        for c in self.inspector.system.get_connections():
            r[c] = []  # expected connections without flows
        for lo in self.logs:
            event = lo.event
            if not isinstance(event, Flow) or lo.property:
                continue  # only collect pure flows, not property updates
            c = cast(Connection, lo.entity)
            cs = r.setdefault(c, [])
            s, t = event.get_source_address(), event.get_target_address()
            cs.append((s, t, event))
        return r

    def get_log(self, entity: Optional[Entity] = None, key: Optional[PropertyKey] = None) \
            -> List[LoggingEvent]:
        """Get log, possibly filtered by entity and key"""
        ent_set = set()

        def add(n: Entity):
            ent_set.add(n)
            for c in n.get_children():
                add(c)
        if entity is not None:
            add(entity)

        r = []
        for lo in self.logs:
            if entity is not None and lo.entity not in ent_set:
                continue
            if key is not None and key in lo.get_properties():
                continue
            r.append(lo)
        return r

    def get_property_sources(self, entity: Entity, keys: Set[PropertyKey]) -> Dict[PropertyKey, EvidenceSource]:
        """Get property sources for an entity and set of properties"""
        r = {}
        for lo in self.logs:
            if lo.entity != entity:
                continue
            ps = lo.get_properties().intersection(keys)
            for p in ps:
                r[p] = lo.event.evidence.source
        return r

    def get_all_property_sources(self) -> Dict[PropertyKey, Dict[EvidenceSource, List[Entity]]]:
        """Get all property sources"""
        r = {}
        for lo in self.logs:
            for p in lo.get_properties():
                r.setdefault(p, {}).setdefault(lo.event.evidence.source, []).append(lo.entity)
        return r
