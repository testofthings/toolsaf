"""Intercept events and create a log of them"""

from logging import Logger
import logging
from typing import Any, List, Set, Tuple, Dict, Optional, cast
from toolsaf.common.address import AnyAddress
from toolsaf.common.verdict import Verdict, Verdictable

from toolsaf.common.entity import Entity
from toolsaf.core.event_interface import EventInterface, PropertyEvent, PropertyAddressEvent
from toolsaf.core.inspector import Inspector
from toolsaf.core.model import IoTSystem, Connection, Host, ModelListener, Service
from toolsaf.common.property import Properties, PropertyKey, PropertySetValue
from toolsaf.core.services import NameEvent
from toolsaf.common.traffic import Evidence, EvidenceSource, HostScan, ServiceScan, Flow, Event


class LoggingEvent:
    """Stored logging event"""
    def __init__(self, event: Event, entity: Optional[Entity] = None,
                 property_value: Optional[Tuple[PropertyKey, Any]] = None) -> None:
        self.event = event
        self.property_value = property_value  # implicit property set
        self.entity = entity
        self.verdict = Verdict.INCON

    def pick_status_verdict(self, entity: Optional[Entity]) -> None:
        """Pick current status verdict"""
        if entity is not None:
            self.entity = entity
            self.verdict = Properties.EXPECTED.get_verdict(entity.properties) or Verdict.INCON

    def resolve_verdict(self) -> Verdict:
        """Resolve verdict"""
        if self.verdict != Verdict.INCON:
            return self.verdict
        if self.property_value:
            value = self.property_value[1]
            if isinstance(value, Verdictable):
                return value.get_verdict()
            if isinstance(value, PropertySetValue) and self.entity:
                return value.get_overall_verdict(self.entity.properties)
        return Verdict.INCON

    def get_properties(self) -> Set[PropertyKey]:
        """Get implicit and explicit properties"""
        r = set()
        if self.property_value:
            r.add(self.property_value[0])
        ev = self.event
        if isinstance(ev, (PropertyEvent, PropertyAddressEvent)):
            r.add(ev.key_value[0])
        if not r:
            r.add(Properties.EXPECTED)  # default property
        return r

    def __repr__(self) -> str:
        v = self.event.get_value_string()
        if self.entity:
            v = f"{self.entity.long_name()} {v}"
        return v


class LoggedData:
    """Logged data collected from event(s)"""
    def __init__(self, verdict: Verdict, info: str) -> None:
        self.verdict = verdict
        self.info = info
        self.properties: List[PropertyKey] = []

    def __repr__(self) -> str:
        return f"{self.verdict.value}: {self.info}"


class EventLogger(EventInterface, ModelListener):
    """Event logger implementation"""
    def __init__(self, inspector: Inspector) -> None:
        super().__init__()
        self.inspector = inspector
        self.logs: List[LoggingEvent] = []
        self.current: Optional[LoggingEvent] = None  # current event
        inspector.system.model_listeners.append(self) # subscribe property events
        self.event_logger: Optional[Logger] = None
        self.logger = logging.getLogger("events")

    def print_event(self, log: LoggingEvent) -> None:
        """Print event for debugging"""
        assert self.event_logger
        s = f"{log.entity.long_name()}" if log.entity else ""
        s = f"{s:<50}"
        verdict = log.resolve_verdict()
        s += verdict.value if verdict != Verdict.INCON else ""
        s = f"{s:<57}"
        s += f" {log.event.get_value_string()}"
        self.event_logger.info(s)

    def _add(self, event: Event, entity: Optional[Entity] = None,
             property_value: Optional[Tuple[PropertyKey, Any]] = None) -> LoggingEvent:
        """Add new current log entry"""
        ev = LoggingEvent(event, entity, property_value)
        self.logs.append(ev)
        self.current = ev
        return ev

    def reset(self) -> None:
        """Reset the log"""
        self.logs.clear()
        self.inspector.reset()

    def get_system(self) -> IoTSystem:
        return self.inspector.system

    def property_change(self, entity: Entity, value: Tuple[PropertyKey, Any]) -> None:
        if self.current is None:
            self.logger.warning("Property change without event to assign it: %s", value[0])
            return
        # make sure the final property value logged
        self.current.property_value = value

    def connection(self, flow: Flow) -> Optional[Connection]:
        lo = self._add(flow)
        e = self.inspector.connection(flow)
        if e is None:
            return None
        lo.pick_status_verdict(e)
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def name(self, event: NameEvent) -> Optional[Host]:
        lo = self._add(event)
        e = self.inspector.name(event)
        if e is None:
            return None  # redundant event, no actions
        lo.pick_status_verdict(e)
        if self.event_logger:
            self.print_event(lo)
        self.current = None
        return e

    def property_update(self, update: PropertyEvent) -> Optional[Entity]:
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
        r: Dict[Connection, List[Tuple[AnyAddress, AnyAddress, Flow]]] = {}
        for c in self.inspector.system.get_connections():
            r[c] = []  # expected connections without flows
        for lo in self.logs:
            event = lo.event
            if not isinstance(event, Flow) or lo.property_value:
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

        def add(n: Entity) -> None:
            ent_set.add(n)
            for c in n.get_children():
                add(c)
        if entity is not None:
            add(entity)

        r = []
        for lo in self.logs:
            if entity is not None and lo.entity not in ent_set:
                continue
            if key is not None and key not in lo.get_properties():
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
        r: Dict[PropertyKey, Dict[EvidenceSource, List[Entity]]] = {}
        for lo in self.logs:
            for p in lo.get_properties():
                if lo.entity:
                    r.setdefault(p, {}).setdefault(lo.event.evidence.source, []).append(lo.entity)
        return r

    def collect_evidence_log_data(self, source: EvidenceSource) -> Dict[Evidence, List[LoggedData]]:
        """Collect batch log data"""
        r: Dict[Evidence, List[LoggedData]] = {}
        for lo in self.logs:
            if lo.event.evidence.source != source:
                continue
            data = LoggedData(lo.resolve_verdict(), lo.event.get_info())
            data.properties = sorted(lo.get_properties())
            r.setdefault(lo.event.evidence, []).append(data)
        return r

    def collect_entity_log_data(self, source: EvidenceSource) -> Dict[Entity, List[LoggedData]]:
        """Collect entity log data"""
        r: Dict[Entity, List[LoggedData]] = {}
        for lo in self.logs:
            if lo.event.evidence.source != source or not lo.entity:
                continue
            data = LoggedData(lo.resolve_verdict(), lo.event.get_info())
            data.properties = sorted(lo.get_properties())
            r.setdefault(lo.entity, []).append(data)
        return r
