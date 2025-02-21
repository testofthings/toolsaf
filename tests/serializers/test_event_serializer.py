from datetime import datetime
from toolsaf.common.address import EndpointAddress, IPAddress, Protocol
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.serializer.event_serializers import EventSerializer
from toolsaf.core.serializer.event_serializers import (
    IPFlowSerializer,
    ServiceScanSerializer, HostScanSerializer, PropertyAddresssEventSerializer
)
from toolsaf.common.traffic import (
    Evidence, EvidenceSource, IPFlow, HostScan, ServiceScan,
    HWAddress, IPAddress
)
from toolsaf.core.event_interface import PropertyAddressEvent
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict


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


def test_ip_flow_serializer():
    source = EvidenceSource(name="Test")
    ip_flow = IPFlow(Evidence(source),
        source=(HWAddress("00:00:00:00:00:00"), IPAddress("1.1.1.1"), 10),
        target=(HWAddress("00:00:00:00:00:00"), IPAddress("1.1.1.1"), 10),
        protocol=Protocol.TCP
    )
    ip_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0)

    assert _get_serialized_event(ip_flow) == {
        "type": "ip-flow",
        "source-id": "id1",
        "source": ["00:00:00:00:00:00|hw", "1.1.1.1", 10],
        "target": ["00:00:00:00:00:00|hw", "1.1.1.1", 10],
        "protocol": "tcp",
        "timestamp": "2025-01-01T00:00:00",
    }


def test_new_ip_flow_from_serialized():
    source = EvidenceSource(name="Test", base_ref="../test.json")
    ip_flow = IPFlow(Evidence(source),
        source=(HWAddress("00:00:00:00:00:00"), IPAddress("1.1.1.1"), 10),
        target=(HWAddress("00:00:00:00:00:00"), IPAddress("1.1.1.1"), 10),
        protocol=Protocol.TCP
    )
    ip_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0)
    stream = _get_stream(ip_flow)

    new_ip_flow = IPFlowSerializer().new(stream)
    assert new_ip_flow.source == (HWAddress("00:00:00:00:00:00"), IPAddress.new("1.1.1.1"), 10)
    assert new_ip_flow.target == (HWAddress("00:00:00:00:00:00"), IPAddress.new("1.1.1.1"), 10)
    assert new_ip_flow.protocol == Protocol.TCP
    assert new_ip_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0)
    assert new_ip_flow.evidence.source.name == "Test"


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


def test_serialize_property_address_event():
    source = EvidenceSource(name="Test")
    property_address_event = PropertyAddressEvent(
        Evidence(source), IPAddress.new("1.1.1.1"),
        PropertyKey("test-key").verdict(Verdict.PASS, "test explanation")
    )

    # PropertyVerdictValue
    assert _get_serialized_event(property_address_event) == {
        "type": "property-address-event",
        "source-id": "id1",
        "address": "1.1.1.1",
        "key": "test-key",
        "verdict": "Pass",
        "explanation": "test explanation"
    }

    # PropertySetValue
    property_address_event = PropertyAddressEvent(
        Evidence(source), IPAddress.new("1.1.1.1"),
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    serialized_event = _get_serialized_event(property_address_event)
    assert "value-key" in serialized_event["sub-keys"]
    assert "key-value" in serialized_event["sub-keys"]
    serialized_event.pop("sub-keys")

    assert serialized_event== {
        "type": "property-address-event",
        "source-id": "id1",
        "address": "1.1.1.1",
        "key": "test-key",
        "explanation": ""
    }


def test_new_property_address_event_from_serialized():
    source = EvidenceSource(name="Test")
    address = IPAddress.new("1.1.1.1")
    property_address_event = PropertyAddressEvent(
        Evidence(source), address,
        PropertyKey("test-key").verdict(Verdict.PASS, "test explanation")
    )
    stream = _get_stream(property_address_event)

    new_property_address_event = PropertyAddresssEventSerializer().new(stream)
    assert new_property_address_event.address == address
    assert new_property_address_event.key_value == PropertyKey("test-key").verdict(Verdict.PASS, "test explanation")
    assert new_property_address_event.evidence.source.name == "Test"

    property_address_event = PropertyAddressEvent(
        Evidence(source), address,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    stream = _get_stream(property_address_event)

    new_property_address_event = PropertyAddresssEventSerializer().new(stream)
    assert new_property_address_event.address == address
    assert new_property_address_event.key_value == PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
