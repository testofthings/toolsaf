"""Serializing events"""

from typing import Any, Dict, Iterable, Union, Tuple
import datetime

from toolsaf.core.model import EvidenceNetworkSource
from toolsaf.common.address import (
    Addresses, EndpointAddress, Protocol, HWAddress, IPAddress, EntityTag, DNSName
)
from toolsaf.common.traffic import (
    Event, Evidence, EvidenceSource,
    EthernetFlow, IPFlow, BLEAdvertisementFlow, HostScan, ServiceScan
)
from toolsaf.common.serializer.serializer import Serializer, SerializerStream
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.verdict import Verdict
from toolsaf.common.release_info import ReleaseInfo
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
                tag = ent.get_tag()
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
        if obj.timestamp:
            stream += "timestamp", obj.timestamp.isoformat()

    def new(self, stream: SerializerStream) -> EthernetFlow:
        ev = EventSerializer.read_evidence(stream)
        flow = EthernetFlow(
            ev,
            source=HWAddress.new(stream["source"].replace("|hw", "")),
            target=HWAddress.new(stream["target"].replace("|hw", "")),
            protocol=Protocol(stream["protocol"]),
            payload=stream.get("payload") or -1
        )
        flow.timestamp = datetime.datetime.fromisoformat(stream["timestamp"])
        return flow

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
        if obj.timestamp:
            stream += "timestamp", obj.timestamp.isoformat()

    def new(self, stream: SerializerStream) -> IPFlow:
        ev = EventSerializer.read_evidence(stream)
        source = stream["source"]
        target = stream["target"]
        flow = IPFlow(
            ev,
            source=(HWAddress.new(source[0].replace("|hw", "")), IPAddress.new(source[1]), source[2]),
            target=(HWAddress.new(target[0].replace("|hw", "")), IPAddress.new(target[1]), target[2]),
            protocol=Protocol(stream["protocol"])
        )
        flow.timestamp = datetime.datetime.fromisoformat(stream["timestamp"])
        return flow


class BLEAdvertisementFlowSerializer(Serializer[BLEAdvertisementFlow]):
    """Serialize BLE advertisement flows"""
    def __init__(self) -> None:
        super().__init__(BLEAdvertisementFlow)
        self.config.with_id = False
        self.config.map_simple_fields("event_type")

    def write(self, obj: BLEAdvertisementFlow, stream: SerializerStream) -> None:
        stream += "source", obj.source.get_parseable_value()
        stream += "timestamp", obj.timestamp.isoformat() if obj.timestamp else ""

    def new(self, stream: SerializerStream) -> BLEAdvertisementFlow:
        ev = EventSerializer.read_evidence(stream)
        ble_flow = BLEAdvertisementFlow(ev,
            source=HWAddress.new(stream["source"].replace("|hw", "")),
            event_type=stream["event_type"]
        )
        if stream.get("timestamp"):
            ble_flow.timestamp = datetime.datetime.fromisoformat(stream["timestamp"])
        return ble_flow


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
            ev, endpoint=Addresses.parse_endpoint(stream["address"]),
            service_name=stream.get("service_name") or ""
        )


class HostScanSerializer(Serializer[HostScan]):
    """Service scan serializer"""
    def __init__(self) -> None:
        super().__init__(HostScan)
        self.config.with_id = False

    def write(self, obj: Any, stream: SerializerStream) -> None:
        stream += "host", obj.host.get_parseable_value()
        stream += "endpoints", [e.get_parseable_value() for e in obj.endpoints]

    def new(self, stream: SerializerStream) -> HostScan:
        ev = EventSerializer.read_evidence(stream)
        eps = []
        for  a in stream["endpoints"]:
            addr = Addresses.parse_endpoint(a)
            assert isinstance(addr, EndpointAddress)
            eps.append(addr)
        return HostScan(ev, host=Addresses.parse_endpoint(stream["host"]), endpoints=set(eps))


class PropertyAddresssEventSerializer(Serializer[PropertyAddressEvent]):
    """PropertyAddressEvent serializer"""
    def __init__(self) -> None:
        super().__init__(PropertyAddressEvent)
        self.config.with_id = False

    def write(self, obj: PropertyAddressEvent, stream: SerializerStream) -> None:
        stream += "address", obj.address.get_parseable_value()
        stream += "key", obj.key_value[0].get_name()
        if isinstance(obj.key_value[1], PropertyVerdictValue):
            stream += "verdict", obj.key_value[1].verdict.value
        else: # PropertySetValue
            sub_keys= [key.get_name() for key in obj.key_value[1].sub_keys]
            stream += "sub-keys", sub_keys
        stream += "explanation", obj.key_value[1].explanation

    def new(self, stream: SerializerStream) -> PropertyAddressEvent:
        ev = EventSerializer.read_evidence(stream)
        key_value: Tuple[PropertyKey, Union[PropertyVerdictValue, PropertySetValue]]
        if (verdict := stream.get("verdict")):
            key_value = PropertyKey(stream["key"]), PropertyVerdictValue(Verdict(verdict), stream["explanation"])
        else:
            sub_keys = {PropertyKey(key) for key in stream["sub-keys"]}
            key_value = PropertyKey(stream["key"]), PropertySetValue(sub_keys, stream["explanation"])
        return PropertyAddressEvent(
            ev, address=Addresses.parse_endpoint(stream["address"]),
            key_value=key_value
        )


class PropertyEventSerializer(Serializer[PropertyEvent]):
    """PropertyEvent serializer"""
    def __init__(self) -> None:
        super().__init__(PropertyEvent)
        self.config.with_id = False

    def write(self, obj: PropertyEvent, stream: SerializerStream) -> None:
        stream += "address", obj.entity.get_system_address().get_parseable_value()
        stream += "key", obj.key_value[0].get_name()
        if isinstance(obj.key_value[1], ReleaseInfo):
            if obj.key_value[1].first_release:
                stream += "first-release", obj.key_value[1].first_release.isoformat()
            stream += "interval-days", obj.key_value[1].interval_days
            if obj.key_value[1].latest_release:
                stream += "latest-release", obj.key_value[1].latest_release.isoformat()
            stream += "latest-release-name", obj.key_value[1].latest_release_name
            stream += "sw-name", obj.key_value[1].sw_name
        else:
            if isinstance(obj.key_value[1], PropertyVerdictValue):
                stream += "verdict", obj.key_value[1].verdict.value
            else:
                sub_keys= [key.get_name() for key in obj.key_value[1].sub_keys]
                stream += "sub-keys", sub_keys

            stream += "explanation", obj.key_value[1].explanation

    def new(self, stream: SerializerStream) -> PropertyEvent:
        ev = EventSerializer.read_evidence(stream)
        if not (address_str := stream.get("address")):
            raise ValueError("Address is missing")
        address = Addresses.parse_system_address(address_str)
        key_value: Tuple[PropertyKey, Union[PropertyVerdictValue, PropertySetValue, ReleaseInfo]]
        if (sw_name := stream.get("sw-name")): # ReleaseInfo
            info = ReleaseInfo(sw_name)
            if (val := stream.get("first-release")):
                info.first_release = datetime.datetime.fromisoformat(val)
            info.interval_days = stream.get("interval-days")
            if (val := stream.get("latest-release")):
                info.latest_release = datetime.datetime.fromisoformat(val)
            info.latest_release_name = stream.get("latest-release-name") or "?"

            key_value = (PropertyKey(stream["key"]), info)

        elif (verdict := stream.get("verdict")): # PropertyVerdictValue
            key_value = PropertyKey(stream["key"]), PropertyVerdictValue(Verdict(verdict), stream["explanation"])
        else: # PropertySetValue
            sub_keys = {PropertyKey(key) for key in stream["sub-keys"]}
            key_value = PropertyKey(stream["key"]), PropertySetValue(sub_keys, stream["explanation"])

        if not (entity := self.system.find_endpoint(address)):
            raise ValueError(f"Entity not found for address {address}")

        return PropertyEvent(
            ev, entity=entity, key_value=key_value
        )


class NameEventSerializer(Serializer[NameEvent]):
    """NameEvent serializer"""
    def __init__(self) -> None:
        super().__init__(NameEvent)
        self.config.with_id = False

    def write(self, obj: NameEvent, stream: SerializerStream) -> None:
        if obj.name:
            stream += "name", obj.name.name
        stream += "peers", [peer.get_system_address().get_parseable_value() for peer in obj.peers]
        if obj.service:
            stream += "service", obj.service.get_system_address().get_parseable_value()
        if obj.tag:
            stream += "tag", obj.tag.tag
        if obj.address:
            stream += "address", obj.address.get_parseable_value()

    def new(self, stream: SerializerStream) -> NameEvent:
        ev = EventSerializer.read_evidence(stream)
        if (v := stream.get("service")):
            service = self.system.find_endpoint(Addresses.parse_system_address(v))
            assert isinstance(service, DNSService)
        else:
            service = None

        name = DNSName(v) if (v := stream.get("name")) else None
        tag = EntityTag.new(v) if (v := stream.get("tag")) else None
        name_event = NameEvent(ev, service, name=name, tag=tag)

        if (v := stream.get("address")):
            name_event.address = Addresses.parse_address(v)

        peers = []
        for entry in stream["peers"]:
            peer = self.system.find_endpoint(Addresses.parse_system_address(entry))
            assert isinstance(peer, Addressable)
            peers.append(peer)
        name_event.peers = peers

        return name_event
