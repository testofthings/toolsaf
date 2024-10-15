"""Event registry backed by database"""

import logging
from typing import Optional, Dict, Self, Any, Set

from tdsaf.core.entity import Entity
from tdsaf.entity_database import EntityDatabase, InMemoryDatabase
from tdsaf.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from tdsaf.event_logger import EventLogger
from tdsaf.inspector import Inspector
from tdsaf.model import IoTSystem, Connection, Host, Service
from tdsaf.services import NameEvent
from tdsaf.core.traffic import ServiceScan, HostScan, Event, EvidenceSource, Flow


class Registry(EventInterface):
    """Record, store, and recall events as required"""
    def __init__(self, inspector: Inspector, db: EntityDatabase = None):
        self.logger = logging.getLogger("registry")
        self.logging = EventLogger(inspector)
        self.system = inspector.system
        self.all_evidence: Set[EvidenceSource] = set()
        self.evidence_filter: Dict[str, bool] = {}  # key is label, not present == False
        if db is None:
            self.database: EntityDatabase = InMemoryDatabase()
        else:
            self.database = db

    def finish_model_load(self) -> Self:
        """Finish loading model, prepare for operation"""
        for e in self.database.restore_stored(self.logging):
            # events already stored
            self.evidence_filter.setdefault(e.evidence.source.label, True)
            self.all_evidence.add(e.evidence.source)
            self.logging.consume(e)
        return self

    def get_id(self, entity) -> int:
        """Get ID for an entity or whatever, int"""
        return self.database.get_id(entity)

    def get_entity(self, id_value: int) -> Optional[Any]:
        """Get entity by id, if any"""
        return self.database.get_entity(id_value)

    def _new_event(self, event: Event):
        """Handle new event"""
        self.database.put_event(event)
        # all sources are enabled by default
        self.evidence_filter.setdefault(event.evidence.source.label, True)
        # Note: evidence filter not updated, it only applies to stored events
        self.all_evidence.add(event.evidence.source)

    def reset(self, evidence_filter: Dict[EvidenceSource, bool] = None, enable_all=False) -> Self:
        """Reset the model by applying the evidence again, potentially filtered"""
        if enable_all:
            s_filter = {e.label: True for e in sorted(self.all_evidence, key=lambda x: x.name)}
        else:
            s_filter = {e.label: v for e, v in (evidence_filter.items() if evidence_filter else [])}
        self.evidence_filter = s_filter
        self.database.reset(s_filter)
        if evidence_filter is not None:
            self.logger.info("filter: %s", " ".join([f"{e.name}={v}" for e, v in evidence_filter.items()]))
        # must call logging reset _after_ database reset, as system events are send with logging reset
        self.logging.reset()
        return self

    def clear_database(self) -> Self:
        """Clear the database, from the disk"""
        self.database.clear_database()
        return self

    def apply_all_events(self) -> Self:
        """Apply all stored events, after reset"""
        while True:
            e = self.database.next_pending()
            if e is None:
                break
            self.logging.consume(e)
        return self

    def get_system(self) -> IoTSystem:
        return self.system

    def connection(self, flow: Flow) -> Optional[Connection]:
        e = self.logging.connection(flow)
        if e is not None:
            self._new_event(flow)
        return e

    def name(self, event: NameEvent) -> Optional[Host]:
        self._new_event(event)
        return self.logging.name(event)

    def property_update(self, update: PropertyEvent) -> Optional[Entity]:
        self._new_event(update)
        return self.logging.property_update(update)

    def property_address_update(self, update: PropertyAddressEvent) -> Optional[Entity]:
        self._new_event(update)
        return self.logging.property_address_update(update)

    def service_scan(self, scan: ServiceScan) -> Optional[Service]:
        self._new_event(scan)
        return self.logging.service_scan(scan)

    def host_scan(self, scan: HostScan) -> Optional[Host]:
        self._new_event(scan)
        return self.logging.host_scan(scan)

    def __repr__(self):
        return self.logging.__repr__()
