"""Event (de)serialization"""
import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Annotated, Union, Literal, Tuple
from pydantic import Field, TypeAdapter

from toolsaf.common.address import (
    AnyAddress, Addresses, EndpointAddress, Protocol,
    HWAddress, IPAddress, EntityTag, DNSName
)
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.release_info import ReleaseInfo
from toolsaf.common.traffic import (
    Event, Evidence, EvidenceSource, Flow, EthernetFlow,
    IPFlow, BLEAdvertisementFlow, HostScan, ServiceScan
)
from toolsaf.common.verdict import Verdict
from toolsaf.core.event_interface import PropertyAddressEvent, PropertyEvent
from toolsaf.core.model import IoTSystem, Addressable, EvidenceNetworkSource
from toolsaf.core.serializer.model_serializer import BaseDTO
from toolsaf.core.services import NameEvent, DNSService


UnionEventDTO = Annotated[
    Union[
        "EvidenceSourceDTO",
        "EthernetFlowDTO",
        "IPFlowDTO",
        "BLEAdvertisementFlowDTO",
        "ServiceScanDTO",
        "HostScanDTO",
        "PropertyAddressEventDTO",
        "PropertyEventDTO",
        "NameEventDTO",
    ],
    Field(discriminator="type")
]
EVENT_ADAPTER: TypeAdapter[UnionEventDTO] = TypeAdapter(UnionEventDTO)


class EventSerializer:
    """Serialize and deserialize EvidenceSources and events"""
    def __init__(self, system: IoTSystem) -> None:
        self.system = system
        self._serialized_sources: Dict[int, str] = {}   # id(source), source_id
        self._source_counter: int = 0
        self.source_map: Dict[str, EvidenceSource] = {}  # source_id, source
        self.serializer_map: Dict[type, Callable[..., Dict[str, Any]]] = {
            EthernetFlow: self._serialize_ethernet_flow,
            IPFlow: self._serialize_ip_flow,
            BLEAdvertisementFlow: self._serialize_ble_flow,
            ServiceScan: self._serialize_service_scan,
            HostScan: self._serialize_host_scan,
            PropertyAddressEvent: self._serialize_property_address_event,
            PropertyEvent: self._serialize_property_event,
            NameEvent: self._serialize_name_event,
        }

    def serialize(self, event: Event) -> List[Dict[str, Any]]:
        """
        Serialize an event.
        If the event's EvidenceSource hasn't been serialized before, returns serialized source and event
        """
        if not (serializer := self.serializer_map.get(type(event))):
            raise ValueError(f"Unsupported event type: {type(event)}")
        source_dict, source_id = self._get_or_create_source_id(event.evidence.source)
        event_dict = serializer(event, source_id)
        return [source_dict, event_dict] if source_dict else [event_dict]

    def deserialize(self, data: Dict[str, Any]) -> Any:
        """Deserialize EvidenceSource or Event from JSON"""
        dto = EVENT_ADAPTER.validate_python(data)
        return dto.to_model(self.source_map, self.system)

    def _get_or_create_source_id(
        self, source: EvidenceSource
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """Return's serialized EvidenceSource and an incremented ID if new, else None and existing id"""
        if (key := id(source)) in self._serialized_sources:
            return None, self._serialized_sources[key]
        self._source_counter += 1
        source_id = f"id{self._source_counter}"
        self._serialized_sources[key] = source_id
        return self._serialize_evidence_source(source, source_id), source_id

    def _serialize_properties(self, properties: Dict[PropertyKey, Any]) -> Dict[str, Any]:
        """Serialize a properties dict using the existing get_value_json format"""
        return {k.get_name(): k.get_value_json(v, {}) for k, v in properties.items()}

    def _serialize_key_value(self, key: PropertyKey, value: Any) -> Tuple[str, Dict[str, Any]]:
        """Serialize a property key-value pair, returning (key_name, value_dict)"""
        val: Dict[str, Any] = {}
        if isinstance(value, ReleaseInfo):
            val["sw_name"] = value.sw_name
            val["interval_days"] = value.interval_days
            val["latest_release_name"] = value.latest_release_name
            if value.first_release:
                val["first_release"] = value.first_release.isoformat()
            if value.latest_release:
                val["latest_release"] = value.latest_release.isoformat()
        elif isinstance(value, PropertyVerdictValue):
            val["verdict"] = value.verdict.value
            val["explanation"] = value.explanation
        elif isinstance(value, PropertySetValue):
            val["sub_keys"] = [k.get_name() for k in value.sub_keys]
            val["explanation"] = value.explanation
        return key.get_name(), val

    def _serialize_evidence_source(self, source: EvidenceSource, source_id: str) -> Dict[str, Any]:
        """Serialize an EvidenceSource to a dict"""
        data: Dict[str, Any] = {
            "type": "source",
            "id": source_id,
            "name": source.name,
            "tool_label": source.label,
            "target": source.target,
            "description": source.description,
            "location": source.location,
            "base_ref": Path(source.base_ref).name,
        }
        if source.timestamp:
            data["timestamp"] = source.timestamp.isoformat()
        if isinstance(source, EvidenceNetworkSource) and source.address_map:
            address_map = []
            for addr, entity in source.address_map.items():
                tag = entity.get_system_address()
                if addr == tag:
                    continue
                address_map.append({
                    "address": addr.get_parseable_value(),
                    "entity": tag.get_parseable_value(),
                })
            data["address_map"] = address_map
        return data

    def _serialize_flow(self, flow: Flow, source_id: str, data: Dict[str, Any]) -> None:
        """Serialize a Flow"""
        data["source_id"] = source_id
        data["protocol"] = flow.protocol.value
        if flow.timestamp:
            data["timestamp"] = flow.timestamp.isoformat()
        if flow.properties:
            data["properties"] = self._serialize_properties(flow.properties)
        if flow.evidence.tail_ref:
            data["tail_ref"] = flow.evidence.tail_ref

    def _serialize_ethernet_flow(self, flow: EthernetFlow, source_id: str) -> Dict[str, Any]:
        """Serialize an EthernetFlow"""
        data: Dict[str, Any] = {
            "type": "ethernet-flow",
            "source": flow.source.get_parseable_value(),
            "target": flow.target.get_parseable_value(),
            "payload": flow.payload
        }
        self._serialize_flow(flow, source_id, data)
        return data

    def _serialize_ip_flow(self, flow: IPFlow, source_id: str) -> Dict[str, Any]:
        """Serialize an IPFlow"""
        source, target = flow.source, flow.target
        data: Dict[str, Any] = {
            "type": "ip-flow",
            "source": [source[0].get_parseable_value(), source[1].get_parseable_value(), source[2]],
            "target": [target[0].get_parseable_value(), target[1].get_parseable_value(), target[2]],
        }
        self._serialize_flow(flow, source_id, data)
        return data

    def _serialize_ble_flow(self, flow: BLEAdvertisementFlow, source_id: str) -> Dict[str, Any]:
        """Serialize a BLEAdvertisementFlow"""
        data: Dict[str, Any] = {
            "type": "ble-advertisement-flow",
            "source": flow.source.get_parseable_value(),
            "event_type": flow.event_type,
        }
        self._serialize_flow(flow, source_id, data)
        return data

    def _serialize_service_scan(self, scan: ServiceScan, source_id: str) -> Dict[str, Any]:
        """Serialize a ServiceScan"""
        return {
            "type": "service-scan",
            "source_id": source_id,
            "service_name": scan.service_name,
            "address": scan.endpoint.get_parseable_value(),
        }

    def _serialize_host_scan(self, scan: HostScan, source_id: str) -> Dict[str, Any]:
        """Serialize a HostScan"""
        return {
            "type": "host-scan",
            "source_id": source_id,
            "host": scan.host.get_parseable_value(),
            "endpoints": [e.get_parseable_value() for e in scan.endpoints],
        }

    def _serialize_property_address_event(
        self, event: PropertyAddressEvent, source_id: str
    ) -> Dict[str, Any]:
        """Serialize a PropertyAddressEvent"""
        key, value = event.key_value
        key_name, value_dict = self._serialize_key_value(key, value)
        return {
            "type": "property-address-event",
            "source_id": source_id,
            "address": event.address.get_parseable_value(),
            "key": key_name,
            "value": value_dict,
        }

    def _serialize_property_event(self, event: PropertyEvent, source_id: str) -> Dict[str, Any]:
        """Serialize a PropertyEvent"""
        key, value = event.key_value
        key_name, value_dict = self._serialize_key_value(key, value)
        return {
            "type": "property-event",
            "source_id": source_id,
            "address": event.entity.get_system_address().get_parseable_value(),
            "key": key_name,
            "value": value_dict,
        }

    def _serialize_name_event(self, event: NameEvent, source_id: str) -> Dict[str, Any]:
        """Serialize a NameEvent"""
        data: Dict[str, Any] = {
            "type": "name-event",
            "source_id": source_id,
            "peers": [peer.get_system_address().get_parseable_value() for peer in event.peers],
        }
        if event.service:
            data["service"] = event.service.get_system_address().get_parseable_value()
        if event.name:
            data["name"] = event.name.name
        if event.tag:
            data["tag"] = event.tag.tag
        if event.address:
            data["address"] = event.address.get_parseable_value()
        if event.timestamp:
            data["timestamp"] = event.timestamp.isoformat()
        return data


def _deserialize_properties(data: Dict[str, Any]) -> Dict[PropertyKey, Any]:
    """Deserialize properties dict"""
    result: Dict[PropertyKey, Any] = {}
    for key_name, value in data.items():
        key = PropertyKey.parse(key_name)
        result[key] = key.decode_value_json(value)
    return result


def _deserialize_key_value(key_name: str, value_dict: Dict[str, Any]) -> Tuple[PropertyKey, Any]:
    """Deserialize a property key-value pair from key_name and a value_dict"""
    property_key = PropertyKey.parse(key_name)
    if "sw_name" in value_dict:
        info = ReleaseInfo(value_dict["sw_name"])
        info.interval_days = value_dict.get("interval_days")
        info.latest_release_name = value_dict.get("latest_release_name") or "?"
        if (val := value_dict.get("first_release")):
            info.first_release = datetime.datetime.fromisoformat(val)
        if (val := value_dict.get("latest_release")):
            info.latest_release = datetime.datetime.fromisoformat(val)
        return property_key, info
    explanation = value_dict.get("explanation", "")
    if "verdict" in value_dict:
        verdict = Verdict.parse(value_dict["verdict"])
        return property_key, PropertyVerdictValue(verdict, explanation)
    sub_keys = {PropertyKey.parse(k) for k in value_dict.get("sub_keys", [])}
    return property_key, PropertySetValue(sub_keys, explanation)


class EvidenceSourceDTO(BaseDTO):
    """DTO for EvidenceSource"""
    id: str
    type: Literal["source"] = "source"
    name: str
    tool_label: str
    target: str
    description: str
    location: str
    base_ref: str
    timestamp: Optional[str] = None
    address_map: Optional[List[Dict[str, str]]] = None

    def to_model(self, source_map: Dict[str, EvidenceSource], system: IoTSystem) -> EvidenceNetworkSource:
        """Create and register an EvidenceNetworkSource from this DTO"""
        source = EvidenceNetworkSource(name=self.name, base_ref=self.base_ref, label=self.tool_label)
        source.target = self.target
        source.description = self.description
        source.location = self.location
        if self.timestamp:
            source.timestamp = datetime.datetime.fromisoformat(self.timestamp)
        if self.address_map:
            for entry in self.address_map:
                address = Addresses.parse_endpoint(entry["address"])
                system_address = Addresses.parse_system_address(entry["entity"])
                entity = system.find_entity(system_address)
                if entity is not None and isinstance(entity, Addressable):
                    source.address_map[address] = entity
        source_map[self.id] = source
        return source


class BaseEventDTO(BaseDTO):
    """Base DTO for all event types"""
    source_id: str
    tail_ref: Optional[str] = None

    def get_evidence(self, source_map: Dict[str, EvidenceSource]) -> Evidence:
        """Build Evidence from the source_map"""
        return Evidence(source_map[self.source_id], self.tail_ref or "")


class FlowDTO(BaseEventDTO):
    """DTO for Flow"""
    protocol: Protocol
    timestamp: Optional[str] = None
    properties: Dict[str, Any] = {}

    def populate(self, flow: Flow) -> None:
        """Populate a Flow with the common fields in FlowDTO"""
        flow.protocol = self.protocol
        if self.timestamp:
            flow.timestamp = datetime.datetime.fromisoformat(self.timestamp)
        flow.properties = _deserialize_properties(self.properties)


class EthernetFlowDTO(FlowDTO):
    """DTO for EthernetFlow"""
    type: Literal["ethernet-flow"] = "ethernet-flow"
    source: str
    target: str
    payload: int

    def to_model(self, source_map: Dict[str, EvidenceSource], _system: IoTSystem) -> EthernetFlow:
        """Create an EthernetFlow from this DTO"""
        flow = EthernetFlow(
            self.get_evidence(source_map),
            source=HWAddress.new(self.source.replace("|hw", "")),
            target=HWAddress.new(self.target.replace("|hw", "")),
            payload=self.payload,
            protocol=self.protocol
        )
        self.populate(flow)
        return flow


class IPFlowDTO(FlowDTO):
    """DTO for IPFlow"""
    type: Literal["ip-flow"] = "ip-flow"
    source: Tuple[str, str, int]
    target: Tuple[str, str, int]

    def to_model(self, source_map: Dict[str, EvidenceSource], _system: IoTSystem) -> IPFlow:
        """Create an IPFlow from this DTO"""
        hw_s, ip_s, port_s = self.source
        hw_t, ip_t, port_t = self.target
        flow = IPFlow(
            self.get_evidence(source_map),
            source=(HWAddress.new(hw_s.replace("|hw", "")), IPAddress.new(ip_s), port_s),
            target=(HWAddress.new(hw_t.replace("|hw", "")), IPAddress.new(ip_t), port_t),
            protocol=Protocol(self.protocol)
        )
        self.populate(flow)
        return flow


class BLEAdvertisementFlowDTO(FlowDTO):
    """DTO for BLEAdvertisementFlow"""
    type: Literal["ble-advertisement-flow"] = "ble-advertisement-flow"
    source: str
    event_type: int

    def to_model(self, source_map: Dict[str, EvidenceSource], _system: IoTSystem) -> BLEAdvertisementFlow:
        """Create a BLEAdvertisementFlow from this DTO"""
        flow = BLEAdvertisementFlow(
            self.get_evidence(source_map),
            source=HWAddress.new(self.source.replace("|hw", "")),
            event_type=self.event_type
        )
        self.populate(flow)
        return flow


class ServiceScanDTO(BaseEventDTO):
    """DTO for ServiceScan"""
    type: Literal["service-scan"] = "service-scan"
    service_name: str
    address: str

    def to_model(self, source_map: Dict[str, EvidenceSource], _system: IoTSystem) -> ServiceScan:
        """Create a ServiceScan from this DTO"""
        return ServiceScan(
            self.get_evidence(source_map),
            endpoint=Addresses.parse_endpoint(self.address),
            service_name=self.service_name
        )


class HostScanDTO(BaseEventDTO):
    """DTO for HostScan"""
    type: Literal["host-scan"] = "host-scan"
    host: str
    endpoints: List[str]

    def to_model(self, source_map: Dict[str, EvidenceSource], _system: IoTSystem) -> HostScan:
        """Create a HostScan from this DTO"""
        parsed_endpoints: set[EndpointAddress] = set()
        for ep_str in self.endpoints:
            endpoint = Addresses.parse_endpoint(ep_str)
            assert isinstance(endpoint, EndpointAddress)
            parsed_endpoints.add(endpoint)
        return HostScan(
            self.get_evidence(source_map),
            host=Addresses.parse_endpoint(self.host),
            endpoints=parsed_endpoints
        )


class PropertyAddressEventDTO(BaseEventDTO):
    """DTO for PropertyAddressEvent"""
    type: Literal["property-address-event"] = "property-address-event"
    address: str
    key: str
    value: Dict[str, Any]

    def to_model(self, source_map: Dict[str, EvidenceSource], _system: IoTSystem) -> PropertyAddressEvent:
        """Create a PropertyAddressEvent from this DTO"""
        return PropertyAddressEvent(
            self.get_evidence(source_map),
            address=Addresses.parse_endpoint(self.address),
            key_value=_deserialize_key_value(self.key, self.value)
        )


class PropertyEventDTO(BaseEventDTO):
    """DTO for PropertyEvent"""
    type: Literal["property-event"] = "property-event"
    address: str  # "" means the IoTSystem root entity
    key: str
    value: Dict[str, Any]

    def to_model(self, source_map: Dict[str, EvidenceSource], system: IoTSystem) -> PropertyEvent:
        """Create a PropertyEvent from this DTO"""
        if self.address == "":
            return PropertyEvent(
                self.get_evidence(source_map),
                entity=system,
                key_value=_deserialize_key_value(self.key, self.value)
            )
        system_address = Addresses.parse_system_address(self.address)
        entity = system.find_endpoint(system_address)
        assert entity is not None, f"Entity not found for address: {self.address}"
        return PropertyEvent(
            self.get_evidence(source_map),
            entity=entity,
            key_value=_deserialize_key_value(self.key, self.value)
        )


class NameEventDTO(BaseEventDTO):
    """DTO for NameEvent"""
    type: Literal["name-event"] = "name-event"
    name: Optional[str] = None
    tag: Optional[str] = None
    service: Optional[str] = None
    address: Optional[str] = None
    peers: List[str] = []
    timestamp: Optional[str] = None

    def to_model(self, source_map: Dict[str, EvidenceSource], system: IoTSystem) -> NameEvent:
        """Create a NameEvent from this DTO"""
        service: Optional[DNSService] = None
        if self.service:
            svc = system.find_endpoint(Addresses.parse_system_address(self.service))
            assert isinstance(svc, DNSService)
            service = svc
        name = DNSName(self.name) if self.name else None
        tag = EntityTag.new(self.tag) if self.tag else None
        address: Optional[AnyAddress] = Addresses.parse_address(self.address) if self.address else None
        peers: List[Addressable] = []
        for peer_str in self.peers:
            peer = system.find_endpoint(Addresses.parse_system_address(peer_str))
            if peer is not None and isinstance(peer, Addressable):
                peers.append(peer)
        event = NameEvent(
            self.get_evidence(source_map),
            service=service,
            name=name,
            tag=tag,
            address=address,
            peers=peers
        )
        if self.timestamp:
            event.timestamp = datetime.datetime.fromisoformat(self.timestamp)
        return event
