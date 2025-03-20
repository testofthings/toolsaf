from datetime import datetime
from toolsaf.common.address import EndpointAddress, IPAddress, Protocol
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.serializer.event_serializers import EventSerializer
from toolsaf.core.serializer.event_serializers import (
    EvidenceSourceSerializer,
    EthernetFlowSerializer, IPFlowSerializer, BLEAdvertisementFlowSerializer,
    ServiceScanSerializer, HostScanSerializer, PropertyAddresssEventSerializer,
    PropertyEventSerializer
)
from toolsaf.common.traffic import (
    Evidence, EvidenceSource, EthernetFlow, IPFlow, BLEAdvertisementFlow,
    HostScan, ServiceScan, HWAddress, IPAddress
)
from toolsaf.core.event_interface import PropertyAddressEvent, PropertyEvent
from toolsaf.core.model import IoTSystem
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict
from toolsaf.common.release_info import ReleaseInfo
from tests.test_model import Setup


SOURCE = EvidenceSource(name="Test", base_ref="../test.json")
HWADDRESS = HWAddress.new("00:00:00:00:00:00")
IPADDRESS = IPAddress.new("1.1.1.1")
SYSTEM = Setup().get_system()


def test_serialize_event_source():
    serializer = EventSerializer(SYSTEM)
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


def test_new_event_source_from_serialized():
    serializer = EventSerializer(SYSTEM)
    stream = SerializerStream(serializer)

    source = EvidenceSource(name="TestSource1", base_ref="../test1.json", label="test-label")
    source.timestamp = datetime(2025, 1, 1, 0, 0, 0)

    stream = next(stream.write(source))
    new_source = EvidenceSourceSerializer().new(stream)
    assert new_source.name == source.name
    assert new_source.base_ref == source.base_ref
    assert new_source.label == source.label
    assert new_source.timestamp == source.timestamp
    assert new_source.target == source.target


def _get_serialized_event(event, system: IoTSystem=IoTSystem()):
    serializer = EventSerializer(system)
    stream = SerializerStream(serializer)
    result = []
    result.extend(serializer.write_event(event, stream))
    return result[1]


def _get_stream(event, system: IoTSystem=IoTSystem()):
    serializer = EventSerializer(system)
    stream = SerializerStream(serializer)
    result = []
    result.extend(serializer.write_event(event, stream))
    return stream


def test_ethernet_flow_serializer():
    ethernet_flow = EthernetFlow(
        Evidence(SOURCE),
        source=HWADDRESS,
        target=HWADDRESS,
        payload=5
    )
    ethernet_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0)

    assert _get_serialized_event(ethernet_flow) == {
        "type": "ethernet-flow",
        "source-id": "id1",
        "source": "00:00:00:00:00:00|hw",
        "target": "00:00:00:00:00:00|hw",
        "protocol": "eth",
        "payload": 5,
        "timestamp": "2025-01-01T00:00:00"
    }


def test_new_ethernet_flow_from_serialized():
    ethernet_flow = EthernetFlow(
        Evidence(SOURCE),
        source=HWADDRESS,
        target=HWADDRESS,
        payload=5
    )
    ethernet_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0)
    stream = _get_stream(ethernet_flow)

    new_ethernet_flow = EthernetFlowSerializer().new(stream)
    assert new_ethernet_flow.source == HWADDRESS
    assert new_ethernet_flow.target == HWADDRESS
    assert new_ethernet_flow.payload == 5
    assert new_ethernet_flow.protocol == Protocol.ETHERNET
    assert new_ethernet_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0)
    assert new_ethernet_flow.evidence.source.name == "Test"


def test_ip_flow_serializer():
    ip_flow = IPFlow(Evidence(SOURCE),
        source=(HWADDRESS, IPADDRESS, 10),
        target=(HWADDRESS, IPADDRESS, 10),
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
    ip_flow = IPFlow(Evidence(SOURCE),
        source=(HWADDRESS, IPADDRESS, 10),
        target=(HWADDRESS, IPADDRESS, 10),
        protocol=Protocol.TCP
    )
    ip_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0)
    stream = _get_stream(ip_flow)

    new_ip_flow = IPFlowSerializer().new(stream)
    assert new_ip_flow.source == (HWADDRESS, IPADDRESS, 10)
    assert new_ip_flow.target == (HWADDRESS, IPADDRESS, 10)
    assert new_ip_flow.protocol == Protocol.TCP
    assert new_ip_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0)
    assert new_ip_flow.evidence.source.name == "Test"


def test_ble_advertisement_flow_serializer():
    ble_flow = BLEAdvertisementFlow(Evidence(SOURCE),
        source=HWADDRESS,
        event_type=0x03
    )

    assert _get_serialized_event(ble_flow) == {
        "type": "ble-advertisement-flow",
        "source-id": "id1",
        "source": "00:00:00:00:00:00|hw",
        "event_type": 3,
        "timestamp": ""
    }

    ble_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0)
    assert _get_serialized_event(ble_flow)["timestamp"] == "2025-01-01T00:00:00"


def test_new_ble_advertisement_flow_from_serialized():
    ble_flow = BLEAdvertisementFlow(Evidence(SOURCE),
        source=HWADDRESS,
        event_type=0x03
    )
    ble_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0)
    stream = _get_stream(ble_flow)

    new_ble_flow = BLEAdvertisementFlowSerializer().new(stream)
    assert new_ble_flow.source == HWADDRESS
    assert new_ble_flow.event_type == 0x03
    assert new_ble_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0)
    assert new_ble_flow.evidence.source.name == "Test"



def test_serialize_service_scan():
    service_scan = ServiceScan(Evidence(SOURCE),
        EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000), service_name="test-name"
    )

    assert _get_serialized_event(service_scan) == {
        "type": "service-scan",
        "source-id": "id1",
        "service_name": "test-name",
        "address": "127.0.0.1/tcp:8000"
    }


def test_new_service_scan_from_serialized():
    service_scan = ServiceScan(
        Evidence(SOURCE), EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000), service_name="test-name"
    )
    stream = _get_stream(service_scan)

    new_service_scan = ServiceScanSerializer().new(stream)
    assert new_service_scan.endpoint == EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000)
    assert new_service_scan.service_name == "test-name"
    assert new_service_scan.evidence.source.name == "Test"
    assert new_service_scan.evidence.source.base_ref == "../test.json"


def test_serialize_host_scan():
    host_scan = HostScan(
        Evidence(SOURCE), IPADDRESS, endpoints=[
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
    endpoints = [
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8000),
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8002),
    ]
    host_scan = HostScan(
        Evidence(SOURCE), IPADDRESS, endpoints=endpoints
    )
    stream = _get_stream(host_scan)

    new_host_scan = HostScanSerializer().new(stream)
    assert new_host_scan.host == IPADDRESS
    assert endpoints[0] in new_host_scan.endpoints
    assert endpoints[1] in new_host_scan.endpoints
    assert new_host_scan.evidence.source.name == "Test"
    assert new_host_scan.evidence.source.base_ref == "../test.json"


def test_serialize_property_address_event():
    property_address_event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
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
        Evidence(SOURCE), IPADDRESS,
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
    property_address_event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey("test-key").verdict(Verdict.PASS, "test explanation")
    )
    stream = _get_stream(property_address_event)

    new_property_address_event = PropertyAddresssEventSerializer().new(stream)
    assert new_property_address_event.address == IPADDRESS
    assert new_property_address_event.key_value == PropertyKey("test-key").verdict(Verdict.PASS, "test explanation")
    assert new_property_address_event.evidence.source.name == "Test"

    property_address_event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    stream = _get_stream(property_address_event)

    new_property_address_event = PropertyAddresssEventSerializer().new(stream)
    assert new_property_address_event.address == IPADDRESS
    assert new_property_address_event.key_value == PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})


def test_serialize_property_event():
    setup = Setup()
    software = setup.system.device("Test Device").software("Test Software").sw

    # PropertyVerdictValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey("test-key").verdict(Verdict.PASS, "test explanation")
    )
    serialized_event = _get_serialized_event(property_event)
    assert serialized_event == {
        "type": "property-event",
        "source-id": "id1",
        "address": "Test_Device&software=Test_Software",
        "key": "test-key",
        "verdict": "Pass",
        "explanation": "test explanation"
    }

    # PropertySetValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    serialized_event = _get_serialized_event(property_event)
    assert "value-key" in serialized_event["sub-keys"]
    assert "key-value" in serialized_event["sub-keys"]
    serialized_event.pop("sub-keys")
    assert serialized_event == {
        "type": "property-event",
        "source-id": "id1",
        "address": "Test_Device&software=Test_Software",
        "key": "test-key",
        "explanation": ""
    }

    # ReleaseInfo
    info = ReleaseInfo("SwRelease")
    info.first_release = datetime(2025, 1, 1, 0, 0, 0)
    info.latest_release = datetime(2025, 1, 1, 0, 0, 0)
    info.latest_release_name = "test-name"
    info.interval_days = 1
    info.sw_name = "test-name2"
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        (ReleaseInfo.PROPERTY_KEY, info)
    )
    serialized_event = _get_serialized_event(property_event)
    assert serialized_event == {
        "type": "property-event",
        "source-id": "id1",
        "address": "Test_Device&software=Test_Software",
        "key": ReleaseInfo.PROPERTY_KEY.get_name(),
        "first-release": datetime(2025, 1, 1, 0, 0, 0).isoformat(),
        "latest-release": datetime(2025, 1, 1, 0, 0, 0).isoformat(),
        "latest-release-name": "test-name",
        "interval-days": 1,
        "sw-name": "test-name2"
    }


def test_new_property_event_from_serialized():
    setup = Setup()
    system = setup.get_system()
    software = setup.system.device("Test Device").software("Test Software").sw

    # PropertyVerdictValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey("test-key").verdict(Verdict.PASS, "test explanation")
    )
    stream = _get_stream(property_event, system)

    new_property_event = list(stream.read([stream.data]))[0]
    assert property_event.entity == new_property_event.entity
    assert property_event.key_value == new_property_event.key_value

    # PropertySetValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    js = _get_stream(property_event, system)
    property_event_serializer = PropertyEventSerializer()
    property_event_serializer.system = system
    new_property_event = property_event_serializer.new(js)

    assert property_event.entity == new_property_event.entity
    assert property_event.key_value == new_property_event.key_value

    # ReleaseInfo
    info = ReleaseInfo("SwRelease")
    info.first_release = datetime(2025, 1, 1, 0, 0, 0)
    info.latest_release = datetime(2025, 1, 1, 0, 0, 0)
    info.latest_release_name = "test-name"
    info.interval_days = 1
    info.sw_name = "test-name2"
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        (ReleaseInfo.PROPERTY_KEY, info)
    )
    stream = _get_stream(property_event, system)

    new_property_event = list(stream.read([stream.data]))[0]
    assert property_event.entity == new_property_event.entity
    assert new_property_event.key_value == new_property_event.key_value