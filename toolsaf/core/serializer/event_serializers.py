"""Serializing events"""

from typing import Any, Dict, Iterable

from toolsaf.common.address import Addresses, EndpointAddress
from toolsaf.common.traffic import Event, Evidence, EvidenceSource, HostScan, ServiceScan
from toolsaf.common.serializer.serializer import GenericSerializer, SerializerStream


class EventSerializer(GenericSerializer[Event]):
    """Base class for event serializers"""
    def __init__(self) -> None:
        super().__init__(Event)
        self.config.with_id = False  # not all events are hashable, which is fine, we do not refer events

    def write(self, obj: Event, stream: SerializerStream) -> None:
        # merge evidence data here
        ev = obj.evidence
        stream.write_object_id("source-id", ev.source)
        if ev.tail_ref:
            stream.write_field("ref", ev.tail_ref)

    @classmethod
    def read_evidence(cls, stream: SerializerStream) -> Evidence:
        """Read evidence from stream"""
        source = stream.resolve("source-id", of_type=EvidenceSource)
        tail_ref = stream.get("tail-ref") or ""
        return Evidence(source, tail_ref)


class EvidenceSourceSerializer(GenericSerializer[EvidenceSource]):
    """Serialize evidence source"""
    def __init__(self) -> None:
        super().__init__(EvidenceSource)
        self.config.map_simple_fields("name", "label", "target", "base_ref")
        # must map classes to have type information in the JSON
        self.config.map_new_class("source", self)
        self.config.map_new_class("event", EventSerializer())
        self.config.map_new_class("service-scan", ServiceScanSerializer())
        self.config.map_new_class("host-scan", HostScanSerializer())

    def write(self, obj: EvidenceSource, stream: SerializerStream) -> None:
        if obj.timestamp:
            stream.write_field("timestamp", obj.timestamp.isoformat())

    def write_event(self, event: Event, stream: SerializerStream) -> Iterable[Dict[str, Any]]:
        """Write event, prefix with sources as required"""
        source = event.evidence.source
        if source not in stream:
            yield from stream.write(source)  # write source first
        yield from stream.write(event)


class ServiceScanSerializer(GenericSerializer[ServiceScan]):
    """Service scan serializer"""
    def __init__(self) -> None:
        super().__init__(ServiceScan)
        self.config.with_id = False
        self.config.map_simple_fields("service_name")

    def write(self, obj: ServiceScan, stream: SerializerStream) -> None:
        stream.write_field("address", obj.endpoint.get_parseable_value())

    def new(self, stream: SerializerStream) -> Any:
        ev = EventSerializer.read_evidence(stream)
        return ServiceScan(ev, endpoint=Addresses.parse_endpoint(stream["address"]))


class HostScanSerializer(GenericSerializer[HostScan]):
    """Service scan serializer"""
    def __init__(self) -> None:
        super().__init__(HostScan)
        self.config.with_id = False

    def write(self, obj: Any, stream: SerializerStream) -> None:
        stream.write_field("host", obj.host.get_parseable_value())
        stream.write_field("endpoints", [e.get_parseable_value() for e in obj.endpoints])

    def new(self, stream: SerializerStream) -> Any:
        ev = EventSerializer.read_evidence(stream)
        eps = []
        for  a in stream["endpoints"]:
            addr = Addresses.parse_endpoint(a)
            assert isinstance(addr, EndpointAddress)
            eps.append(addr)
        return HostScan(ev, host=Addresses.parse_endpoint(stream["host"]), endpoints=set(eps))
