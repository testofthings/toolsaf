"""Event interface to consume model events"""

from typing import Dict, List, Optional, Type, Callable, Any, Tuple

from toolsaf.common.address import AnyAddress
from toolsaf.common.verdict import Verdict
from toolsaf.common.entity import Entity
from toolsaf.core.model import Connection, Host, IoTSystem, Service
from toolsaf.common.property import PropertyKey
from toolsaf.core.services import NameEvent
from toolsaf.common.traffic import ServiceScan, HostScan, Event, Flow, IPFlow, EthernetFlow, BLEAdvertisementFlow, \
    Evidence
from toolsaf.common.verdict import Verdictable


class EventInterface:
    """Event interface"""
    def __init__(self) -> None:
        self.consume_methods: Dict[Type[Event], Callable[[Any], Any]] = {
            IPFlow: self.connection,
            EthernetFlow: self.connection,
            BLEAdvertisementFlow: self.connection,
            NameEvent: self.name,
            PropertyEvent: self.property_update,
            PropertyAddressEvent: self.property_address_update,
            ServiceScan: self.service_scan,
            HostScan: self.host_scan,
        }

    def get_system(self) -> IoTSystem:
        """Access system model"""
        raise NotImplementedError()

    def connection(self, flow: Flow) -> Optional[Connection]:
        """Inspect the given flow"""
        raise NotImplementedError()

    def name(self, event: NameEvent) -> Optional[Host]:
        """Learn a name"""
        raise NotImplementedError()

    def property_update(self, update: 'PropertyEvent') -> Optional[Entity]:
        """Update to property value"""
        raise NotImplementedError()

    def property_address_update(self, update: 'PropertyAddressEvent') -> Optional[Entity]:
        """Update to property value by address"""
        raise NotImplementedError()

    def service_scan(self, scan: ServiceScan) -> Optional[Service]:
        """The given address has a service"""
        raise NotImplementedError()

    def host_scan(self, scan: HostScan) -> Optional[Host]:
        """The given host have these services and not other ones"""
        raise NotImplementedError()

    def consume(self, event: Event) -> Optional[Entity]:
        """Consume event and call the proper method"""
        m = self.consume_methods[type(event)]
        ent = m(event)
        assert ent is None or isinstance(ent, Entity), "Bad return type from consumed event"
        return ent


class PropertyEvent(Event, Verdictable):
    """Property value event"""
    def __init__(self, evidence: Evidence, entity: Entity, key_value: Tuple[PropertyKey, Any]) -> None:
        super().__init__(evidence)
        self.entity = entity
        self.key_value = key_value

    def get_verdict(self) -> Verdict:
        v = self.key_value[1]
        return v.get_verdict() if isinstance(v, Verdictable) else Verdict.INCON

    def get_info(self) -> str:
        return self.key_value[0].get_explanation(self.key_value[1])

    def get_value_string(self) -> str:
        return f"{self.key_value[0]}: {self.get_info()}"

    def get_properties(self) -> List[PropertyKey]:
        return [self.key_value[0]]

    def __hash__(self) -> int:
        return super().__hash__() ^ hash(self.entity) ^ hash(self.key_value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PropertyEvent):
            return False
        return super().__eq__(other) and self.entity == other.entity and self.key_value == other.key_value


class PropertyAddressEvent(Event, Verdictable):
    """Property value event by address"""
    def __init__(self, evidence: Evidence, address: AnyAddress, key_value: Tuple[PropertyKey, Any]) -> None:
        super().__init__(evidence)
        self.address = address
        self.key_value = key_value

    def get_verdict(self) -> Verdict:
        v = self.key_value[1]
        return v.get_verdict() if isinstance(v, Verdictable) else Verdict.INCON

    def get_info(self) -> str:
        return self.key_value[0].get_explanation(self.key_value[1])

    def get_value_string(self) -> str:
        return f"{self.key_value[0]}: {self.get_info()}"

    def get_properties(self) -> List[PropertyKey]:
        return [self.key_value[0]]

    def __hash__(self) -> int:
        return super().__hash__() ^ hash(self.address) ^ hash(self.key_value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PropertyAddressEvent):
            return False
        return super().__eq__(other) and self.address == other.address and self.key_value == other.key_value
