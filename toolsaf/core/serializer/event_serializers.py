"""Serializing events"""

from typing import Any, Dict, Iterable, Union, Tuple, Optional
import datetime

from toolsaf.core.model import EvidenceNetworkSource
from toolsaf.common.address import (
    Addresses, EndpointAddress, Protocol, HWAddress, IPAddress, EntityTag, DNSName
)
from toolsaf.common.traffic import (
    Event, Evidence, EvidenceSource, Flow,
    EthernetFlow, IPFlow, BLEAdvertisementFlow, HostScan, ServiceScan
)
from toolsaf.common.serializer.serializer import Serializer, SerializerStream
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.verdict import Verdict
from toolsaf.common.release_info import ReleaseInfo
from toolsaf.common.entity import Entity
from toolsaf.core.model import IoTSystem, Addressable
from toolsaf.core.services import NameEvent, DNSService
from toolsaf.core.event_interface import PropertyAddressEvent, PropertyEvent

class EventSerializer(Serializer[Event]):
    """Base class for event serializers"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__(Event)
        self.system = system
        self.config.with_id = False  # not all events are hashable, which is fine, we do not refer events
        # must map classes to have type information in the JSON
        self.config.map_class("event", self)
        self.config.map_class("service-scan", ServiceScanSerializer())
        self.config.map_class("ethernet-flow", EthernetFlowSerializer())
        self.config.map_class("ip-flow", IPFlowSerializer())
        self.config.map_class("ble-advertisement-flow", BLEAdvertisementFlowSerializer())
        self.config.map_class("host-scan", HostScanSerializer())
        self.config.map_class("property-address-event", PropertyAddresssEventSerializer())
        self.config.map_class("property-event", PropertyEventSerializer())
        self.config.map_class("name-event", NameEventSerializer())
        self.config.map_class("source", EvidenceSourceSerializer(system))

    def write_event(self, event: Event, stream: SerializerStream) -> Iterable[Dict[str, Any]]:
        """Write event, prefix with sources as required"""
        source = event.evidence.source
        if source not in stream:
            yield from stream.write(source)  # write source first
        yield from stream.write(event)

    def write(self, obj: Event, stream: SerializerStream) -> None:
        # merge evidence data here
        ev = obj.evidence
        stream.write_object_id("source-id", ev.source)
        if ev.tail_ref:
            stream += "ref", ev.tail_ref

    @classmethod
    def read_evidence(cls, stream: SerializerStream) -> Evidence:
        """Read evidence from stream"""
        source = stream.resolve("source-id", of_type=EvidenceSource)
        tail_ref = stream.get("tail-ref") or ""
        return Evidence(source, tail_ref)


class EvidenceSourceSerializer(Serializer[EvidenceSource]):
    """Serialize evidence source"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__(EvidenceSource)
        self.system = system
        self.config.map_simple_fields("name", "label", "target", "base_ref")

    def write(self, obj: EvidenceSource, stream: SerializerStream) -> None:
        if obj.timestamp:
            stream += "timestamp", obj.timestamp.isoformat()
        if isinstance(obj, EvidenceNetworkSource):
            # a shortcut, all are of this kind?
            # map of address -> entity
            add_map = []
            for add, ent in obj.address_map.items():
                tag = ent.get_system_address()
                if tag is None or add == tag:
                    continue   # pointless to store
                add_map.append({
                    "address": add.get_parseable_value(),
                    "entity": tag.get_parseable_value(),  # by system address
                })
            stream += "address_map", add_map

    def new(self, stream: SerializerStream) -> EvidenceSource:
        # all sources are network sources now
        return EvidenceNetworkSource(name=stream["name"])

    def read(self, obj: EvidenceSource, stream: SerializerStream) -> None:
        ts = stream - "timestamp"
        obj.timestamp = datetime.datetime.fromisoformat(ts) if ts else None
        if isinstance(obj, EvidenceNetworkSource):
            add_map = stream - "address_map"
            if isinstance(add_map, list):
                for add_d in add_map:
                    address = Addresses.parse_endpoint(add_d["address"])
                    system_address = Addresses.parse_system_address(add_d["entity"])
                    ent = self.system.find_entity(system_address)
                    if ent is None:
                        raise ValueError(f"Cannot resolve entity by {system_address}")
                    assert isinstance(ent, Addressable), "Address map contains non-addressable entity"
                    obj.address_map[address] = ent


class FlowSerializer:
    """Flow serializers"""
    @staticmethod
    def write_timestamp(obj: Flow, stream: SerializerStream) -> None:
        """Write timestamp to stream"""
        if obj.timestamp:
            stream += "timestamp", obj.timestamp.isoformat()

    @staticmethod
    def read_timestamp(stream: SerializerStream) -> Optional[datetime.datetime]:
        """Read timestamp from stream"""
        if (timestamp := stream - "timestamp"):
            return datetime.datetime.fromisoformat(timestamp)
        return None

    @staticmethod
    def write_properties(obj: Flow, stream: SerializerStream) -> None:
        """Write properties to stream"""
        if obj.properties:
            stream += "properties", {
                k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()
            }

    @staticmethod
    def read_properties(stream: SerializerStream) -> Dict[PropertyKey, Any]:
        """Read properties from stream"""
        if (properties := stream - "properties"):
            result = {}
            for k, v in properties.items():
                key = PropertyKey.parse(k)
                value = key.decode_value_json(v)
                result[key] = value
            return result
        return {}

class EthernetFlowSerializer(Serializer[EthernetFlow]):
    """Serialize Ethernet flows"""
    def __init__(self) -> None:
        super().__init__(EthernetFlow)
        self.config.with_id = False
        self.config.map_simple_fields("payload")

    def write(self, obj: EthernetFlow, stream: SerializerStream) -> None:
        stream += "protocol", obj.protocol.value
        stream += "source", obj.source.get_parseable_value()
        stream += "target", obj.target.get_parseable_value()
        FlowSerializer.write_timestamp(obj, stream)
        FlowSerializer.write_properties(obj, stream)

    def new(self, stream: SerializerStream) -> EthernetFlow:
        return EthernetFlow.new(Protocol(stream["protocol"]), stream["source"].replace("|hw", ""))

    def read(self, obj: EthernetFlow, stream: SerializerStream) -> None:
        obj.evidence = EventSerializer.read_evidence(stream)
        obj.target = HWAddress.new(stream["target"].replace("|hw", ""))
        obj.payload = stream.get("payload") or -1
        obj.timestamp = FlowSerializer.read_timestamp(stream)
        obj.properties = FlowSerializer.read_properties(stream)


class IPFlowSerializer(Serializer[IPFlow]):
    """Serialize IP flows"""
    def __init__(self) -> None:
        super().__init__(IPFlow)
        self.config.with_id = False

    def write(self, obj: IPFlow, stream: SerializerStream) -> None:
        stream += "protocol", obj.protocol.value
        source, target = obj.source, obj.target
        stream += "source", [
            source[0].get_parseable_value(),
            source[1].get_parseable_value(),
            source[2]
        ]
        stream += "target", [
            target[0].get_parseable_value(),
            target[1].get_parseable_value(),
            target[2]
        ]
        FlowSerializer.write_timestamp(obj, stream)
        FlowSerializer.write_properties(obj, stream)

    def new(self, stream: SerializerStream) -> IPFlow:
        return IPFlow(evidence=EventSerializer.read_evidence(stream))

    def read(self, obj: IPFlow, stream: SerializerStream) -> None:
        hw_addr, ip_addr, port = stream["source"]
        obj.source = (HWAddress.new(hw_addr.replace("|hw", "")), IPAddress.new(ip_addr), port)
        hw_addr, ip_addr, port = stream["target"]
        obj.target = (HWAddress.new(hw_addr.replace("|hw", "")), IPAddress.new(ip_addr), port)
        obj.protocol = Protocol(stream["protocol"])
        obj.timestamp = FlowSerializer.read_timestamp(stream)
        obj.properties = FlowSerializer.read_properties(stream)


class BLEAdvertisementFlowSerializer(Serializer[BLEAdvertisementFlow]):
    """Serialize BLE advertisement flows"""
    def __init__(self) -> None:
        super().__init__(BLEAdvertisementFlow)
        self.config.with_id = False
        self.config.map_simple_fields("event_type")

    def write(self, obj: BLEAdvertisementFlow, stream: SerializerStream) -> None:
        stream += "source", obj.source.get_parseable_value()
        FlowSerializer.write_timestamp(obj, stream)
        FlowSerializer.write_properties(obj, stream)

    def new(self, stream: SerializerStream) -> BLEAdvertisementFlow:
        return BLEAdvertisementFlow(
            EventSerializer.read_evidence(stream),
            HWAddress.new(stream["source"].replace("|hw", "")),
            stream["event_type"]
        )

    def read(self, obj: BLEAdvertisementFlow, stream: SerializerStream) -> None:
        obj.timestamp = FlowSerializer.read_timestamp(stream)
        obj.properties = FlowSerializer.read_properties(stream)


class ServiceScanSerializer(Serializer[ServiceScan]):
    """Service scan serializer"""
    def __init__(self) -> None:
        super().__init__(ServiceScan)
        self.config.with_id = False
        self.config.map_simple_fields("service_name")

    def write(self, obj: ServiceScan, stream: SerializerStream) -> None:
        stream += "address", obj.endpoint.get_parseable_value()

    def new(self, stream: SerializerStream) -> ServiceScan:
        ev = EventSerializer.read_evidence(stream)
        return ServiceScan(
            ev, endpoint=Addresses.parse_endpoint(stream["address"])
        )

    def read(self, obj: ServiceScan, stream: SerializerStream) -> None:
        obj.service_name = stream["service_name"]


class HostScanSerializer(Serializer[HostScan]):
    """Service scan serializer"""
    def __init__(self) -> None:
        super().__init__(HostScan)
        self.config.with_id = False

    def write(self, obj: Any, stream: SerializerStream) -> None:
        stream += "host", obj.host.get_parseable_value()
        stream += "endpoints", [e.get_parseable_value() for e in obj.endpoints]

    def new(self, stream: SerializerStream) -> HostScan:
        return HostScan(
            EventSerializer.read_evidence(stream),
            Addresses.parse_endpoint(stream["host"]),
            set()
        )

    def read(self, obj: HostScan, stream: SerializerStream) -> None:
        endpoints = []
        for entry in stream["endpoints"]:
            endpoint = Addresses.parse_endpoint(entry)
            assert isinstance(endpoint, EndpointAddress)
            endpoints.append(endpoint)
        obj.endpoints = set(endpoints)


class KeyValueSerializer:
    """PropertyEvent and PropertyAddressEvent key_value serializer"""
    @staticmethod
    def write_key_value(obj: Union[PropertyEvent, PropertyAddressEvent], stream: SerializerStream) -> None:
        """Write key value to stream"""
        key, value = obj.key_value
        stream += "key", key.get_name()
        if isinstance(value, ReleaseInfo):
            ReleaseInfoSerializer.write_release_info(value, stream)
            return
        if isinstance(value, PropertyVerdictValue):
            stream += "verdict", value.verdict.value
        elif isinstance(value, PropertySetValue):
            stream += "sub-keys", [k.get_name() for k in value.sub_keys]
        stream += "explanation", value.explanation

    @staticmethod
    def read_key_value(stream: SerializerStream) -> Tuple[PropertyKey, Any]:
        """Read key value from stream"""
        property_key = PropertyKey.parse(stream["key"])
        if stream.get("sw-name"):
            release_info = ReleaseInfoSerializer.read_release_info(stream)
            return (property_key, release_info)

        if (verdict := stream - "verdict"): # PropertyVerdictValue
            property_verdict_value = PropertyVerdictValue(Verdict.parse(verdict), stream["explanation"])
            return (property_key, property_verdict_value)

        # PropertySetValue
        sub_keys = {PropertyKey.parse(key) for key in stream["sub-keys"]}
        property_set_value = PropertySetValue(sub_keys, stream["explanation"])
        return (property_key, property_set_value)


class ReleaseInfoSerializer:
    """ReleaseInfo serializer"""
    @staticmethod
    def write_release_info(obj: ReleaseInfo, stream: SerializerStream) -> None:
        """Write ReleaseInfo to stream"""
        if obj.first_release:
            stream += "first-release", obj.first_release.isoformat()
        stream += "interval-days", obj.interval_days
        if obj.latest_release:
            stream += "latest-release", obj.latest_release.isoformat()
        stream += "latest-release-name", obj.latest_release_name
        stream += "sw-name", obj.sw_name

    @staticmethod
    def read_release_info(stream: SerializerStream) -> ReleaseInfo:
        """Read ReleaseInfo from stream"""
        release_info = ReleaseInfo(stream["sw-name"])
        if (val := stream - "first-release"):
            release_info.first_release = datetime.datetime.fromisoformat(val)
        release_info.interval_days = stream.get("interval-days")
        if (val := stream - "latest-release"):
            release_info.latest_release = datetime.datetime.fromisoformat(val)
        release_info.latest_release_name = stream.get("latest-release-name") or "?"
        return release_info


class PropertyAddresssEventSerializer(Serializer[PropertyAddressEvent]):
    """PropertyAddressEvent serializer"""
    def __init__(self) -> None:
        super().__init__(PropertyAddressEvent)
        self.config.with_id = False

    def write(self, obj: PropertyAddressEvent, stream: SerializerStream) -> None:
        stream += "address", obj.address.get_parseable_value()
        KeyValueSerializer.write_key_value(obj, stream)

    def new(self, stream: SerializerStream) -> PropertyAddressEvent:
        return PropertyAddressEvent(
            EventSerializer.read_evidence(stream),
            Addresses.parse_endpoint(stream["address"]),
            KeyValueSerializer.read_key_value(stream)
        )


class PropertyEventSerializer(Serializer[PropertyEvent]):
    """PropertyEvent serializer"""
    def __init__(self) -> None:
        super().__init__(PropertyEvent)
        self.config.with_id = False

    def write(self, obj: PropertyEvent, stream: SerializerStream) -> None:
        stream += "address", obj.entity.get_system_address().get_parseable_value()
        KeyValueSerializer.write_key_value(obj, stream)

    def new(self, stream: SerializerStream) -> PropertyEvent:
        address = Addresses.parse_system_address(stream["address"])
        entity = self.system.find_endpoint(address)
        assert isinstance(entity, Entity), "Did not find an entity"
        return PropertyEvent(
            EventSerializer.read_evidence(stream),
            entity,
            KeyValueSerializer.read_key_value(stream)
        )


class NameEventSerializer(Serializer[NameEvent]):
    """NameEvent serializer"""
    def __init__(self) -> None:
        super().__init__(NameEvent)
        self.config.with_id = False

    def write(self, obj: NameEvent, stream: SerializerStream) -> None:
        stream += "peers", [peer.get_system_address().get_parseable_value() for peer in obj.peers]
        if obj.service:
            stream += "service", obj.service.get_system_address().get_parseable_value()
        if obj.name:
            stream += "name", obj.name.name
        if obj.tag:
            stream += "tag", obj.tag.tag
        if obj.address:
            stream += "address", obj.address.get_parseable_value()

    def new(self, stream: SerializerStream) -> NameEvent:
        name = DNSName(v) if (v := stream.get("name")) else None
        tag = EntityTag.new(v) if (v := stream.get("tag")) else None
        return NameEvent(
            EventSerializer.read_evidence(stream),
            service=None,
            name=name,
            tag=tag
        )

    def read(self, obj: NameEvent, stream: SerializerStream) -> None:
        if (service_str := stream - "service"):
            service = self.system.find_endpoint(Addresses.parse_system_address(service_str))
            assert isinstance(service, DNSService)
            obj.service = service

        if (address := stream - "address"):
            obj.address = Addresses.parse_address(address)

        peers = []
        for entry in stream["peers"]:
            peer = self.system.find_endpoint(Addresses.parse_system_address(entry))
            assert isinstance(peer, Addressable)
            peers.append(peer)
        obj.peers = peers
