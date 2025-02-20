from datetime import datetime
from toolsaf.common.address import EndpointAddress, IPAddress, Protocol
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.serializer.event_serializers import EventSerializer
from toolsaf.core.serializer.event_serializers import (
    ServiceScanSerializer, HostScanSerializer
)
from toolsaf.common.traffic import Evidence, EvidenceSource, HostScan, ServiceScan


def test_serialize_event_source():
    serializer = EventSerializer()
    stream = SerializerStream(serializer)

    source1 = EvidenceSource(name="TestSource1", base_ref="../test1.json", label="test-label")
    source1.timestamp = datetime(2025, 1, 1, 0, 0, 0)
    source2 = EvidenceSource(name="TestSource2", base_ref="../test2.json", label="test-label")

    assert next(stream.write(source1)) == {
        "id": "id1",
        "type": "source",
        "name": "TestSource1",
        "label": "test-label",
        "target": "",
        "base_ref": "../test1.json",
        "timestamp": "2025-01-01T00:00:00"
    }
    assert next(stream.write(source2))["id"] == "id2"


def _get_serialized_event(event):
    serializer = EventSerializer()
    stream = SerializerStream(serializer)
    result = []
    result.extend(serializer.write_event(event, stream))
    return result[1]


def _get_stream(event):
    serializer = EventSerializer()
    stream = SerializerStream(serializer)
    result = []
    result.extend(serializer.write_event(event, stream))
    return stream


def test_serialize_service_scan():
    source = EvidenceSource(name="Test")
    service_scan = ServiceScan(
        Evidence(source), EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000), service_name="test-name"
    )

    assert _get_serialized_event(service_scan) == {
        "type": "service-scan",
        "source-id": "id1",
        "service_name": "test-name",
        "address": "127.0.0.1/tcp:8000"
    }


def test_new_service_scan_from_serialized():
    source = EvidenceSource(name="Test", base_ref="../test.json")
    service_scan = ServiceScan(
        Evidence(source), EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000), service_name="test-name"
    )
    stream = _get_stream(service_scan)

    new_service_scan = ServiceScanSerializer().new(stream)
    assert new_service_scan.endpoint == EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000)
    assert new_service_scan.service_name == "test-name"
    assert new_service_scan.evidence.source.name == "Test"
    assert new_service_scan.evidence.source.base_ref == "../test.json"


def test_serialize_host_scan():
    source = EvidenceSource(name="Test")
    host_scan = HostScan(
        Evidence(source), IPAddress.new("1.1.1.1"), endpoints=[
            EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8000),
            EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8002),
        ]
    )

    assert _get_serialized_event(host_scan) == {
        "type": "host-scan",
        "source-id": "id1",
        "host": "1.1.1.1",
        "endpoints": ["1.1.1.2/tcp:8000", "1.1.1.2/tcp:8002"]
    }


def test_new_host_scan_from_serialized():
    source = EvidenceSource(name="Test", base_ref="../test.json")
    address = IPAddress.new("1.1.1.1")
    endpoints = [
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8000),
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8002),
    ]
    host_scan = HostScan(
        Evidence(source), address, endpoints=endpoints
    )

    stream = _get_stream(host_scan)

    new_host_scan = HostScanSerializer().new(stream)
    assert new_host_scan.host == address
    assert endpoints[0] in new_host_scan.endpoints
    assert endpoints[1] in new_host_scan.endpoints
    assert new_host_scan.evidence.source.name == "Test"
    assert new_host_scan.evidence.source.base_ref == "../test.json"
