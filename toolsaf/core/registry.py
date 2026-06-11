"""Event registry backed by database"""

import logging
from typing import Optional, Dict, Set

from toolsaf.common.entity import Entity
from toolsaf.core.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from toolsaf.core.event_logger import EventLogger
from toolsaf.core.inspector import Inspector
from toolsaf.core.model import IoTSystem, Connection, Host, Service
from toolsaf.core.services import NameEvent
from toolsaf.common.traffic import ServiceScan, HostScan, EvidenceSource, Flow


class Registry(EventInterface):
    """Record, store, and recall events as required"""
    def __init__(self, inspector: Inspector) -> None:
        super().__init__()
        self.logger = logging.getLogger("registry")
        self.logging = EventLogger(inspector)
        self.system = inspector.system
        self.all_evidence: Set[EvidenceSource] = set()
        self.evidence_filter: Dict[str, bool] = {}  # key is label, not present == False

    def get_system(self) -> IoTSystem:
        return self.system

    def connection(self, flow: Flow) -> Optional[Connection]:
        e = self.logging.connection(flow)
        return e

    def name(self, event: NameEvent) -> Optional[Host]:
        return self.logging.name(event)

    def property_update(self, update: PropertyEvent) -> Optional[Entity]:
        return self.logging.property_update(update)

    def property_address_update(self, update: PropertyAddressEvent) -> Optional[Entity]:
        return self.logging.property_address_update(update)

    def service_scan(self, scan: ServiceScan) -> Optional[Service]:
        return self.logging.service_scan(scan)

    def host_scan(self, scan: HostScan) -> Optional[Host]:
        return self.logging.host_scan(scan)

    def __repr__(self) -> str:
        return self.logging.__repr__()
