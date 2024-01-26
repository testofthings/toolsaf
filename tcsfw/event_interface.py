from typing import Dict, Type, Callable, Any, Tuple

from tcsfw.address import AnyAddress
from tcsfw.entity import Entity
from tcsfw.model import IoTSystem
from tcsfw.property import PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import ServiceScan, HostScan, Event, Flow, IPFlow, EthernetFlow, BLEAdvertisementFlow, Evidence
from tcsfw.verdict import Verdictable, Verdict


class EventInterface:
    def get_system(self) -> IoTSystem:
        """Access system model"""
        raise NotImplementedError()

    def connection(self, flow: Flow):
        """Inspect the given flow"""
        raise NotImplementedError()

    def name(self, event: NameEvent):
        """Learn a name"""
        raise NotImplementedError()

    def property_update(self, update: 'PropertyEvent'):
        """Update to property value"""
        raise NotImplementedError()

    def property_address_update(self, update: 'PropertyAddressEvent'):
        """Update to property value by address"""
        raise NotImplementedError()

    def service_scan(self, scan: ServiceScan):
        """The given address has a service"""
        raise NotImplementedError()

    def host_scan(self, scan: HostScan):
        """The given host have these services and not other ones"""
        raise NotImplementedError()

    def consume(self, event: Event):
        """Consume event and call the proper method"""
        methods: Dict[Type, Callable[[Any], Any]] = {
            IPFlow: self.connection,
            EthernetFlow: self.connection,
            BLEAdvertisementFlow: self.connection,
            NameEvent: self.name,
            PropertyEvent: self.property_update,
            PropertyAddressEvent: self.property_address_update,
            ServiceScan: self.service_scan,
            HostScan: self.host_scan,
        }
        m = methods[type(event)]
        m(event)


class PropertyEvent(Event, Verdictable):
    """Property value event"""
    def __init__(self, evidence: Evidence, entity: Entity, key_value: Tuple[PropertyKey, Any]):
        super().__init__(evidence)
        self.entity = entity
        self.key_value = key_value

    def get_verdict(self) -> Verdict:
        v = self.key_value[1]
        return v.get_verdict() if isinstance(v, Verdictable) else Verdict.INCON

    def get_value_string(self) -> str:
        return self.key_value[0].get_value_string(self.key_value[1])

    def get_comment(self) -> str:
        return self.key_value[0].get_explanation(self.key_value[1])

    def get_info(self) -> str:
        # without entity, at least for event log
        return self.key_value[0].get_value_string(self.key_value[1])


class PropertyAddressEvent(Event, Verdictable):
    """Property value event by address"""
    def __init__(self, evidence: Evidence, address: AnyAddress, key_value: Tuple[PropertyKey, Any]):
        super().__init__(evidence)
        self.address = address
        self.key_value = key_value

    def get_verdict(self) -> Verdict:
        v = self.key_value[1]
        return v.get_verdict() if isinstance(v, Verdictable) else Verdict.INCON

    def get_value_string(self) -> str:
        return self.key_value[0].get_value_string(self.key_value[1])

    def get_comment(self) -> str:
        return self.key_value[0].get_explanation(self.key_value[1])

    def get_info(self) -> str:
        # without entity, at least for event log
        return self.key_value[0].get_value_string(self.key_value[1])
