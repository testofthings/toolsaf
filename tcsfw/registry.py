import logging
from typing import List, Optional, Dict, Self, Any, Tuple

from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from tcsfw.event_logger import EventLogger
from tcsfw.inspector import Inspector
from tcsfw.model import IoTSystem, Connection, Host, Service
from tcsfw.property import PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import ServiceScan, HostScan, Event, EvidenceSource, Flow


class Registry(EventInterface):
    """Record, store, and recall events as required"""
    def __init__(self, inspector: Inspector):
        self.logger = logging.getLogger("registry")
        self.logging = EventLogger(inspector)
        self.system = inspector.system
        self.fallthrough = True
        self.trail: List[Event] = []
        self.trail_filter: Dict[EvidenceSource, bool] = {}  # not present == True
        self.cursor = 0
        # local ID integers for entities and connections, usable for persistent DB
        self.ids: Dict[Any, int] = {}
        self.reverse_id: List[Any] = []

    def get_id(self, entity) -> int:
        """Get ID for an entity or whatever, int"""
        i = self.ids.get(entity, -1)
        if i == -1:
            self.ids[entity] = i = len(self.ids)
            self.reverse_id.append(entity)
        return i

    def get_entity(self, id_value: int) -> Optional:
        """Get entity by id, if any"""
        return self.reverse_id[id_value] if id_value < len(self.reverse_id) else None

    def do_task(self) -> bool:
        """Perform registry task"""
        if self.cursor >= len(self.trail):
            return False
        e = self.trail[self.cursor]
        if self.trail_filter.get(e.evidence.source, True):
            self.logger.info("process #%d %s", self.cursor, e)
            self.logging.consume(e)
        else:
            self.logger.debug("filtered #%d %s", self.cursor, e)
        self.cursor += 1
        return True

    def do_all_tasks(self) -> Self:
        """Do all tasks at once"""
        more = self.do_task()
        while more:
            more = self.do_task()
        return self

    def _new_event(self, event: Event):
        """Handle new event"""
        if self.fallthrough and self.cursor == len(self.trail):
            self.cursor += 1
        self.trail.append(event)
        self.trail_filter.setdefault(event.evidence.source, True)  # update filter as we go

    def reset(self, evidence_filter: Dict[EvidenceSource, bool] = None) -> Self:
        """Reset the model by applying the evidence again, potentially filtered"""
        self.trail_filter = {} if evidence_filter is None else evidence_filter
        self.logging.reset()
        self.cursor = 0  # start from first event
        if evidence_filter is not None:
            self.logger.info("filter: " + " ".join([f"{e.name}={v}" for e, v in evidence_filter.items()]))
        return self

    def get_system(self) -> IoTSystem:
        return self.system

    def connection(self, flow: Flow) -> Optional[Connection]:
        self._new_event(flow)
        if not self.fallthrough:
            return None
        return self.logging.connection(flow)

    def name(self, event: NameEvent) -> Optional[Host]:
        self._new_event(event)
        if not self.fallthrough:
            return None
        return self.logging.name(event)

    def property_update(self, update: PropertyEvent) -> Optional[Entity]:
        self._new_event(update)
        if not self.fallthrough:
            return None
        return self.logging.property_update(update)

    def property_address_update(self, update: PropertyAddressEvent) -> Optional[Entity]:
        self._new_event(update)
        if not self.fallthrough:
            return None
        return self.logging.property_address_update(update)

    def service_scan(self, scan: ServiceScan) -> Optional[Service]:
        self._new_event(scan)
        if not self.fallthrough:
            return None
        return self.logging.service_scan(scan)

    def host_scan(self, scan: HostScan) -> Optional[Host]:
        self._new_event(scan)
        if not self.fallthrough:
            return None
        return self.logging.host_scan(scan)

    def __repr__(self):
        return self.logging.__repr__()
