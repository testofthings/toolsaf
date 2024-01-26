from typing import List, TextIO, Tuple, Dict, Optional, cast
from tcsfw.address import AnyAddress

from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyEvent, PropertyAddressEvent
from tcsfw.inspector import Inspector
from tcsfw.model import IoTSystem, Connection, Host, Service, NetworkNode
from tcsfw.property import Properties, PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import HostScan, ServiceScan, Flow, Event
from tcsfw.verdict import Status, Verdict


class LoggingEvent:
    """Event with logging"""
    def __init__(self, event: Event, key: Tuple[Entity, Optional[PropertyKey]] = None):
        self.key = key
        self.event = event
        self.verdict = Verdict.INCON

    def get_value_string(self) -> str:
        """Get value as string"""
        v = self.event.get_value_string()
        if self.verdict != Verdict.INCON or self.key[0] != Status.EXPECTED:
            st = f"{self.key[0].status.value}/{self.verdict.value}" if self.verdict != Verdict.INCON  \
                else self.key[0].status.value
            v += f" [{st}]" if v else st
        return v

    def __repr__(self):
        return f"{self.key[0].long_name()}: {self.key[1] or '-'} {self.event}"


class EventLogger(EventInterface):
    def __init__(self, inspector: Inspector):
        self.inspector = inspector
        self.logs: List[LoggingEvent] = []

    def print_events(self, writer: TextIO):
        """Print all events for debugging"""
        for lo in self.logs:
            ent, pro = lo.key
            e = lo.event
            s = f"{ent.long_name()},"
            s = f"{s:<40}"
            s += f"{lo.get_value_string()},"
            s = f"{s:<80}"
            s += e.get_comment() or e.evidence.get_reference()
            writer.write(f"{s}\n")

    def _add(self, event: Event, entity: Entity, key: PropertyKey = None) -> LoggingEvent:
        """Add log entry"""
        ev = LoggingEvent(event, (entity, key))
        self.logs.append(ev)
        return ev

    def reset(self):
        """Reset the log"""
        self.logs.clear()
        self.inspector.reset()

    def get_system(self) -> IoTSystem:
        return self.inspector.system

    def connection(self, flow: Flow) -> Connection:
        e = self.inspector.connection(flow)
        lo = self._add(flow, e)
        lo.verdict = Properties.EXPECTED.get_verdict(e.properties) or Verdict.INCON
        return e

    def name(self, event: NameEvent) -> Host:
        e = self.inspector.name(event)
        lo = self._add(event, e)
        lo.verdict = Properties.EXPECTED.get_verdict(e.properties) or Verdict.INCON
        return e

    def property_update(self, update: PropertyEvent) -> Entity:
        e = self.inspector.property_update(update)
        self._add(update, e, update.key_value[0])
        # many properties have verdict in them
        return e

    def property_address_update(self, update: PropertyAddressEvent) -> Entity:
        e = self.inspector.property_address_update(update)
        self._add(update, e, update.key_value[0])
        # many properties have verdict in them
        return e

    def service_scan(self, scan: ServiceScan) -> Service:
        e = self.inspector.service_scan(scan)
        lo = self._add(scan, e)
        lo.verdict = Properties.EXPECTED.get_verdict(e.properties) or Verdict.INCON
        return e

    def host_scan(self, scan: HostScan) -> Host:
        e = self.inspector.host_scan(scan)
        lo = self._add(scan, e)
        lo.verdict = Properties.EXPECTED.get_verdict(e.properties) or Verdict.INCON
        return e

    def collect_flows(self) -> Dict[Connection, List[Tuple[AnyAddress, AnyAddress, Flow]]]:
        """Collect relevant connection flows"""
        r = {}
        for c in self.inspector.system.get_connections():
            r[c] = []  # expected connections without flows
        for lo in self.logs:
            event = lo.event
            if not isinstance(event, Flow):
                continue
            c = cast(Connection, lo.key[0])
            cs = r.setdefault(c, [])
            s, t = event.get_source_address(), event.get_target_address()
            cs.append((s, t, event))
        return r

    def get_log(self, entity: Optional[Entity] = None, key: Optional[PropertyKey] = None) \
            -> List[LoggingEvent]:
        """Get log, possibly filtered by entity and key"""
        key_set = set()
        if entity:
            key_set.add((entity, key))

        def add(n: Entity):
            for k in n.properties.keys():
                key_set.add((n, k))
            for c in n.get_children():
                key_set.add((c, None))
                add(c)
        if entity and key is None:
            # add all properties for the entity
            add(entity)
        if key_set:
            r = [lo for lo in self.logs if lo.key in key_set]
        else:
            r = self.logs
        return r


