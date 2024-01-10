from typing import List, Tuple, Dict, Optional

from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyEvent, PropertyAddressEvent
from tcsfw.inspector import Inspector
from tcsfw.model import IoTSystem, Connection, Host, Service, NetworkNode
from tcsfw.property import PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import Evidence, HostScan, ServiceScan, Flow, Event


# Key to use when none
NullKey = PropertyKey("")


class EventLogger(EventInterface):
    def __init__(self, inspector: Inspector):
        self.inspector = inspector
        self.logs: List[Tuple[Tuple[Entity, PropertyKey], Event]] = []

    def _add(self, event: Event, entity: Entity, key: PropertyKey = None):
        """Add log entry"""
        self.logs.append(((entity, key or NullKey), event))

    def reset(self):
        """Reset the log"""
        self.logs.clear()
        self.inspector.reset()

    def get_system(self) -> IoTSystem:
        return self.inspector.system

    def connection(self, flow: Flow) -> Connection:
        e = self.inspector.connection(flow)
        self._add(flow, e)
        return e

    def name(self, event: NameEvent) -> Host:
        e = self.inspector.name(event)
        self._add(event, e)
        return e

    def property_update(self, update: PropertyEvent) -> Entity:
        e = self.inspector.property_update(update)
        self._add(update, e, update.key_value[0])
        return e

    def property_address_update(self, update: PropertyAddressEvent) -> Entity:
        e = self.inspector.property_address_update(update)
        self._add(update, e, update.key_value[0])
        return e

    def service_scan(self, scan: ServiceScan) -> Service:
        e = self.inspector.service_scan(scan)
        self._add(scan, e)
        return e

    def host_scan(self, scan: HostScan) -> Host:
        e = self.inspector.host_scan(scan)
        self._add(scan, e)
        return e

    def get_log(self, entity: Optional[Entity] = None, key: Optional[PropertyKey] = None) \
            -> List[Tuple[Event, Entity, Optional[PropertyKey]]]:
        """Get log, possibly filtered by entity and key"""
        key_set = set()
        if entity:
            key_set.add((entity, key or NullKey))

        def add(n: Entity):
            for k in n.properties.keys():
                key_set.add((n, k))
            for c in n.get_children():
                key_set.add((c, NullKey))
                add(c)
        if entity and key is None:
            add(entity)
        if key_set:
            r = [(lo[1], lo[0][0], lo[0][1]) for lo in self.logs if lo[0] in key_set]
        else:
            r = [(lo[1], lo[0][0], lo[0][1]) for lo in self.logs]
        return r


