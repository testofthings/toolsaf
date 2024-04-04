from typing import Dict, Optional, Type, Callable, Any, Tuple

from tcsfw.address import Addresses, AnyAddress
from tcsfw.basics import Verdict
from tcsfw.entity import Entity
from tcsfw.model import IoTSystem
from tcsfw.property import PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import ServiceScan, HostScan, Event, Flow, IPFlow, EthernetFlow, BLEAdvertisementFlow, Evidence
from tcsfw.verdict import Verdictable


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

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict:
        k, v = self.key_value
        r = {
            "entity": id_resolver(self.entity),
            "key": k.get_name(),
        }
        k.get_value_json(v, r)
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict, entity_resolver: Callable[[Any], Any]) -> 'PropertyEvent':
        """Decode event from JSON"""
        entity = entity_resolver(data["entity"])
        key = PropertyKey.parse(data["key"])
        ver = Verdict.parse(data.get("verdict"))
        return PropertyEvent(evidence, entity, key.verdict(ver))

    def __hash__(self) -> int:
        return super().__hash__() ^ hash(self.entity) ^ hash(self.key_value)

    def __eq__(self, v) -> bool:
        return super().__eq__(v) and self.entity == v.entity and self.key_value == v.key_value


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

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict:
        k, v = self.key_value
        r = {
            "address": self.address.get_parseable_value(),
            "key": k.get_name(),
        }
        k.get_value_json(v, r)
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict,
                         entity_resolver: Callable[[Any], Any]) -> 'PropertyAddressEvent':
        address = Addresses.parse_endpoint(data["address"])
        key = PropertyKey.parse(data["key"])
        ver = Verdict.parse(data.get("verdict"))
        return PropertyAddressEvent(evidence, address, key.verdict(ver))

    def __hash__(self) -> int:
        return super().__hash__() ^ hash(self.address) ^ hash(self.key_value)

    def __eq__(self, v) -> bool:
        return super().__eq__(v) and self.address == v.address and self.key_value == v.key_value


class EventMap:
    Event_types = {
            "flow-eth": EthernetFlow,
            "flow-ip": IPFlow,
            "flow-ble": BLEAdvertisementFlow,
            "prop-ent": PropertyEvent,
            "prop-add": PropertyAddressEvent,
            "name": NameEvent,
            "scan-service": ServiceScan,
            "scan-host": HostScan,
        }

    Event_names = {v: k for k, v in Event_types.items()}

    @classmethod
    def get_event_class(cls, name: str) -> Optional[Type[Event]]:
        return cls.Event_types.get(name)

    @classmethod
    def get_event_name(cls, event: Type[Event]) -> str:
        return cls.Event_names[event]
