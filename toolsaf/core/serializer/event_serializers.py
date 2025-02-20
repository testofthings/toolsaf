"""Serializing events"""

from typing import Any, Dict, Iterable, Union, Tuple

from toolsaf.common.address import Addresses, EndpointAddress
from toolsaf.common.traffic import Event, Evidence, EvidenceSource, HostScan, ServiceScan
from toolsaf.common.serializer.serializer import Serializer, SerializerStream
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.verdict import Verdict
from toolsaf.core.event_interface import PropertyAddressEvent

class EventSerializer(Serializer[Event]):
    """Base class for event serializers"""
    def __init__(self) -> None:
        super().__init__(Event)
        self.config.with_id = False  # not all events are hashable, which is fine, we do not refer events
        # must map classes to have type information in the JSON
        self.config.map_class("event", self)
        self.config.map_class("service-scan", ServiceScanSerializer())
        self.config.map_class("host-scan", HostScanSerializer())
        self.config.map_class("property-address-event", PropertyAddresssEventSerializer())
        self.config.map_class("source", EvidenceSourceSerializer())

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
    def __init__(self) -> None:
        super().__init__(EvidenceSource)
        self.config.map_simple_fields("name", "label", "target", "base_ref")

    def write(self, obj: EvidenceSource, stream: SerializerStream) -> None:
        if obj.timestamp:
            stream += "timestamp", obj.timestamp.isoformat()


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
        #key_value: Union[Tuple[PropertyKey, PropertyVerdictValue], Tuple[PropertyKey, PropertySetValue]]
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
