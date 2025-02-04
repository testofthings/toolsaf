"""Serializing events"""

from typing import Any, Dict, Iterable, Type

from toolsaf.common.address import Addresses
from toolsaf.common.traffic import Event, Evidence, EvidenceSource, ServiceScan
from toolsaf.common.serializer.serializer import Serializer, SerializerStream


class EventSerializer(Serializer):
    """Base class for event serializers"""
    def __init__(self, class_type: Type[Event]) -> None:
        super().__init__(class_type)
        self.config.with_id = False  # not all events are hashable, which is fine, we do not refer events

    def write(self, obj: Any, stream: SerializerStream) -> None:
        assert isinstance(obj, Event)
        # merge evidence data here
        ev = obj.evidence
        stream.write_object_id("source-id", ev.source)
        if ev.tail_ref:
            stream.write_field("ref", ev.tail_ref)

    def read_evidence(self, stream: SerializerStream) -> Evidence:
        """Read evidence from stream"""
        source = stream.context.id_for(stream["source-id"])
        assert isinstance(source, EvidenceSource)
        tail_ref = stream.get("tail-ref") or ""
        return Evidence(source, tail_ref)


class EvidenceSourceSerializer(Serializer):
    """Serialize evidence source"""
    def __init__(self, class_type: Type[EvidenceSource] = EvidenceSource) -> None:
        super().__init__(class_type)
        self.config.map_simple_fields("name", "label", "target", "base_ref")
        # must map classes to have type information in the JSON
        self.config.map_new_class("source", self)
        self.config.map_new_class("service-scan", ServiceScanSerializer())
        # Fallback for event, for not-implemented serializers
        self.config.map_new_class("event", EventSerializer(class_type=Event))

    def write(self, obj: Any, stream: SerializerStream) -> None:
        assert isinstance(obj, EvidenceSource)
        if obj.timestamp:
            stream.write_field("timestamp", obj.timestamp.isoformat())

    def write_event(self, event: Event, stream: SerializerStream) -> Iterable[Dict[str, Any]]:
        """Write event, prefix with sources as required"""
        source = event.evidence.source
        if source not in stream:
            yield from stream.write(source)  # write source first
        yield from stream.write(event)


class ServiceScanSerializer(EventSerializer):
    """Service scan serializer"""
    def __init__(self) -> None:
        super().__init__(ServiceScan)
        self.config.map_simple_fields("service_name")

    def write(self, obj: Any, stream: SerializerStream) -> None:
        super().write(obj, stream)
        assert isinstance(obj, ServiceScan)
        stream.write_field("address", obj.endpoint.get_parseable_value())

    def new(self, stream: SerializerStream) -> Any:
        ev = self.read_evidence(stream)
        return ServiceScan(ev, endpoint=Addresses.parse_endpoint(stream["address"]))
