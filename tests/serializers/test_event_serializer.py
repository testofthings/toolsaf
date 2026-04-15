from datetime import datetime, timezone
from typing import TypeVar
from toolsaf.main import DNS
from toolsaf.common.address import EndpointAddress, IPAddress, Protocol, EntityTag, DNSName
from toolsaf.core.serializer.event_serializer import EventSerializer
from toolsaf.common.traffic import (
    Evidence, EvidenceSource, EthernetFlow, IPFlow, BLEAdvertisementFlow,
    HostScan, ServiceScan, HWAddress, IPAddress
)
from toolsaf.core.event_interface import PropertyAddressEvent, PropertyEvent
from toolsaf.core.model import IoTSystem
from toolsaf.core.services import NameEvent
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.verdict import Verdict
from toolsaf.common.release_info import ReleaseInfo
from tests.test_model import Setup


SOURCE = EvidenceSource(name="Test", base_ref="../test.json")
HWADDRESS = HWAddress.new("00:00:00:00:00:00")
IPADDRESS = IPAddress.new("1.1.1.1")
SYSTEM = Setup().get_system()

T = TypeVar("T")


def _get_serialized_event(event, system: IoTSystem = IoTSystem()):
    serializer = EventSerializer(system)
    records = serializer.serialize(event)
    return records[-1]


def _get_deserialized_object(obj: T, system: IoTSystem = SYSTEM) -> T:
    serializer = EventSerializer(SYSTEM)
    records = serializer.serialize(obj)

    des = EventSerializer(system)
    result = None
    for record in records:
        result = des.deserialize(record)
    return result


def test_pydantic_serialize_event_source():
    serializer = EventSerializer(SYSTEM)

    source1 = EvidenceSource(
        name="TestSource1", base_ref="../test1.json", label="test-label",
        description="test description", location="test location"
    )
    source1.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    source2 = EvidenceSource(name="TestSource2", base_ref="../test2.json", label="test-label")

    records1 = serializer.serialize(EthernetFlow(Evidence(source1), source=HWADDRESS, target=HWADDRESS))
    assert records1[0] == {
        "id": "id1",
        "type": "source",
        "name": "TestSource1",
        "tool_label": "test-label",
        "target": "",
        "description": "test description",
        "location": "test location",
        "base_ref": "test1.json",
        "timestamp": "2025-01-01T00:00:00+00:00"
    }

    records2 = serializer.serialize(EthernetFlow(Evidence(source2), source=HWADDRESS, target=HWADDRESS))
    source2_json = records2[0]
    assert source2_json["id"] == "id2"
    assert source2_json["description"] == ""
    assert source2_json["location"] == ""


def test_pydantic_new_event_source_from_serialized():
    source = EvidenceSource(name="TestSource1", base_ref="../test1.json", label="test-label")
    source.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    flow = EthernetFlow(Evidence(source), source=HWADDRESS, target=HWADDRESS)
    new_flow = _get_deserialized_object(flow)
    new_source = new_flow.evidence.source
    assert new_source.name == source.name
    assert new_source.base_ref == "test1.json"
    assert new_source.label == source.label
    assert new_source.timestamp == source.timestamp
    assert new_source.target == source.target


def test_pydantic_ethernet_flow_serializer():
    ethernet_flow = EthernetFlow(
        Evidence(SOURCE),
        source=HWADDRESS,
        target=HWADDRESS,
        payload=5
    )
    ethernet_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    assert _get_serialized_event(ethernet_flow) == {
        "type": "ethernet-flow",
        "source_id": "id1",
        "source": "00:00:00:00:00:00|hw",
        "target": "00:00:00:00:00:00|hw",
        "protocol": "eth",
        "payload": 5,
        "timestamp": "2025-01-01T00:00:00+00:00"
    }


def test_pydantic_new_ethernet_flow_from_serialized():
    ethernet_flow = EthernetFlow(
        Evidence(SOURCE),
        source=HWADDRESS,
        target=HWADDRESS,
        payload=5
    )
    ethernet_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    new_ethernet_flow = _get_deserialized_object(ethernet_flow)
    assert new_ethernet_flow.source == HWADDRESS
    assert new_ethernet_flow.target == HWADDRESS
    assert new_ethernet_flow.payload == 5
    assert new_ethernet_flow.protocol == Protocol.ETHERNET
    assert new_ethernet_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert new_ethernet_flow.evidence.source.name == "Test"


def test_pydantic_ip_flow_serializer():
    ip_flow = IPFlow(Evidence(SOURCE, tail_ref=":10"),
        source=(HWADDRESS, IPADDRESS, 10),
        target=(HWADDRESS, IPADDRESS, 10),
        protocol=Protocol.TCP
    )
    ip_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    ip_flow.properties = {
        PropertyKey("test-key"): PropertyVerdictValue(Verdict.PASS, "test"),
        PropertyKey("test-key2"): PropertySetValue({PropertyKey("1"), PropertyKey("2")}, "test2")
    }

    serialized = _get_serialized_event(ip_flow)
    props = serialized.pop("properties")
    assert props["test-key"] == {"verdict": "Pass", "exp": "test"}
    assert props["test-key2"]["exp"] == "test2"
    assert "1" in props["test-key2"]["set"] and "2" in props["test-key2"]["set"]

    assert serialized == {
        "type": "ip-flow",
        "source_id": "id1",
        "source": ["00:00:00:00:00:00|hw", "1.1.1.1", 10],
        "target": ["00:00:00:00:00:00|hw", "1.1.1.1", 10],
        "protocol": "tcp",
        "timestamp": "2025-01-01T00:00:00+00:00",
        "tail_ref": ":10"
    }


def test_pydantic_new_ip_flow_from_serialized():
    ip_flow = IPFlow(Evidence(SOURCE, tail_ref=":10"),
        source=(HWADDRESS, IPADDRESS, 10),
        target=(HWADDRESS, IPADDRESS, 11),
        protocol=Protocol.TCP
    )
    ip_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    ip_flow.properties = {
        PropertyKey("test-key"): PropertyVerdictValue(Verdict.PASS, "test"),
        PropertyKey("test-key2"): PropertySetValue({PropertyKey("1"), PropertyKey("2")}, "test2")
    }

    new_ip_flow = _get_deserialized_object(ip_flow)
    assert new_ip_flow.evidence.tail_ref == ":10"
    assert new_ip_flow.source == (HWADDRESS, IPADDRESS, 10)
    assert new_ip_flow.target == (HWADDRESS, IPADDRESS, 11)
    assert new_ip_flow.protocol == Protocol.TCP
    assert new_ip_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert new_ip_flow.evidence.source.name == "Test"
    assert new_ip_flow.properties[PropertyKey("test-key")] == PropertyVerdictValue(Verdict.PASS, "test")
    assert new_ip_flow.properties[PropertyKey("test-key2")] == PropertySetValue({PropertyKey("1"), PropertyKey("2")}, "test2")


def test_pydantic_ble_advertisement_flow_serializer():
    ble_flow = BLEAdvertisementFlow(Evidence(SOURCE),
        source=HWADDRESS,
        event_type=0x03
    )

    assert _get_serialized_event(ble_flow) == {
        "type": "ble-advertisement-flow",
        "source_id": "id1",
        "source": "00:00:00:00:00:00|hw",
        "protocol": "ble",
        "event_type": 3
    }

    ble_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert _get_serialized_event(ble_flow)["timestamp"] == "2025-01-01T00:00:00+00:00"


def test_pydantic_new_ble_advertisement_flow_from_serialized():
    ble_flow = BLEAdvertisementFlow(Evidence(SOURCE),
        source=HWADDRESS,
        event_type=0x03
    )
    ble_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    new_ble_flow = _get_deserialized_object(ble_flow)
    assert new_ble_flow.source == HWADDRESS
    assert new_ble_flow.event_type == 0x03
    assert new_ble_flow.protocol == ble_flow.protocol
    assert new_ble_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert new_ble_flow.evidence.source.name == "Test"


def test_pydantic_serialize_service_scan():
    service_scan = ServiceScan(Evidence(SOURCE),
        EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000), service_name="test-name"
    )

    assert _get_serialized_event(service_scan) == {
        "type": "service-scan",
        "source_id": "id1",
        "service_name": "test-name",
        "address": "127.0.0.1/tcp:8000"
    }


def test_pydantic_new_service_scan_from_serialized():
    service_scan = ServiceScan(
        Evidence(SOURCE), EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000), service_name="test-name"
    )

    new_service_scan = _get_deserialized_object(service_scan)
    assert new_service_scan.endpoint == EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000)
    assert new_service_scan.service_name == "test-name"
    assert new_service_scan.evidence.source.name == "Test"
    assert new_service_scan.evidence.source.base_ref == "test.json"


def test_pydantic_serialize_host_scan():
    host_scan = HostScan(
        Evidence(SOURCE), IPADDRESS, endpoints=[
            EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8000),
            EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8002),
        ]
    )

    assert _get_serialized_event(host_scan) == {
        "type": "host-scan",
        "source_id": "id1",
        "host": "1.1.1.1",
        "endpoints": ["1.1.1.2/tcp:8000", "1.1.1.2/tcp:8002"]
    }


def test_pydantic_new_host_scan_from_serialized():
    endpoints = [
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8000),
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8002),
    ]
    host_scan = HostScan(
        Evidence(SOURCE), IPADDRESS, endpoints=set(endpoints)
    )

    new_host_scan = _get_deserialized_object(host_scan)
    assert new_host_scan.host == IPADDRESS
    assert endpoints[0] in new_host_scan.endpoints
    assert endpoints[1] in new_host_scan.endpoints
    assert new_host_scan.evidence.source.name == "Test"
    assert new_host_scan.evidence.source.base_ref == "test.json"


def test_pydantic_serialize_property_address_event():
    property_address_event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey.parse("test-key:abc").verdict(Verdict.PASS, "test explanation")
    )

    assert _get_serialized_event(property_address_event) == {
        "type": "property-address-event",
        "source_id": "id1",
        "address": "1.1.1.1",
        "key": "test-key:abc",
        "value": {"verdict": "Pass", "explanation": "test explanation"}
    }

    property_address_event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    serialized_event = _get_serialized_event(property_address_event)
    assert "value-key" in serialized_event["value"]["sub_keys"]
    assert "key-value" in serialized_event["value"]["sub_keys"]
    assert serialized_event["value"]["explanation"] == ""
    serialized_event.pop("value")

    assert serialized_event == {
        "type": "property-address-event",
        "source_id": "id1",
        "address": "1.1.1.1",
        "key": "test-key"
    }


def test_pydantic_new_property_address_event_from_serialized():
    property_address_event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey.parse("test-key:abc").verdict(Verdict.PASS, "test explanation")
    )

    new_property_address_event = _get_deserialized_object(property_address_event)
    assert new_property_address_event.address == IPADDRESS
    assert new_property_address_event.key_value == PropertyKey.parse("test-key:abc").verdict(Verdict.PASS, "test explanation")
    assert new_property_address_event.evidence.source.name == "Test"

    property_address_event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey.parse("test-key:abc").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )

    new_property_address_event = _get_deserialized_object(property_address_event)
    assert new_property_address_event.address == IPADDRESS
    assert new_property_address_event.key_value == PropertyKey.parse("test-key:abc").value_set({PropertyKey("value-key"), PropertyKey("key-value")})


def test_pydantic_serialize_property_event():
    setup = Setup()
    software = setup.system.device("Test Device").software("Test Software").sw

    # PropertyVerdictValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey("test-key:abc").verdict(Verdict.PASS, "test explanation")
    )
    serialized_event = _get_serialized_event(property_event)
    assert serialized_event == {
        "type": "property-event",
        "source_id": "id1",
        "address": "Test_Device&software=Test_Software",
        "key": "test-key:abc",
        "value": {"verdict": "Pass", "explanation": "test explanation"}
    }

    # PropertySetValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    serialized_event = _get_serialized_event(property_event)
    assert "value-key" in serialized_event["value"]["sub_keys"]
    assert "key-value" in serialized_event["value"]["sub_keys"]
    serialized_event.pop("value")
    assert serialized_event == {
        "type": "property-event",
        "source_id": "id1",
        "address": "Test_Device&software=Test_Software",
        "key": "test-key"
    }

    # ReleaseInfo
    info = ReleaseInfo("SwRelease")
    info.first_release = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    info.latest_release = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
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
        "source_id": "id1",
        "address": "Test_Device&software=Test_Software",
        "key": ReleaseInfo.PROPERTY_KEY.get_name(),
        "value": {
            "sw_name": "test-name2",
            "first_release": datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc).isoformat(),
            "latest_release": datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc).isoformat(),
            "latest_release_name": "test-name",
            "interval_days": 1
        }
    }


def test_pydantic_new_property_event_from_serialized():
    setup = Setup()
    system = setup.get_system()
    software = setup.system.device("Test Device").software("Test Software").sw

    # PropertyVerdictValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey.parse("test-key:abc").verdict(Verdict.PASS, "test explanation")
    )

    new_property_event = _get_deserialized_object(property_event, system)
    assert property_event.entity == new_property_event.entity
    assert property_event.key_value == new_property_event.key_value

    # PropertySetValue
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey.parse("test-key:abc").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )

    new_property_event = _get_deserialized_object(property_event, system)
    assert property_event.entity == new_property_event.entity
    assert property_event.key_value == new_property_event.key_value

    # ReleaseInfo
    info = ReleaseInfo("SwRelease")
    info.first_release = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    info.latest_release = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    info.latest_release_name = "test-name"
    info.interval_days = 1
    info.sw_name = "test-name2"
    property_event = PropertyEvent(
        Evidence(SOURCE), software,
        (ReleaseInfo.PROPERTY_KEY, info)
    )

    new_property_event = _get_deserialized_object(property_event, system)
    assert property_event.entity == new_property_event.entity
    assert new_property_event.key_value == new_property_event.key_value


def test_pydantic_serialize_name_event():
    setup = Setup()
    services = setup.system.any("Services")
    device = setup.system.device("Test Device")
    device >> services / DNS

    name_event = NameEvent(
        Evidence(SOURCE),
        services.entity.children[0],
        DNSName("test.com"),
        EntityTag.new("test-tag"),
        IPADDRESS,
        [device.entity, services.entity.children[0]]
    )
    assert _get_serialized_event(name_event) == {
        "type": "name-event",
        "source_id": "id1",
        "name": "test.com",
        "peers": ["Test_Device", "Services/udp:53"],
        "service": "Services/udp:53",
        "tag": "test-tag",
        "address": "1.1.1.1"
    }


def test_pydantic_new_name_event_from_serialized():
    setup = Setup()
    services = setup.system.any("Services")
    device = setup.system.device("Test Device")
    device >> services / DNS
    name_event = NameEvent(
        Evidence(SOURCE),
        services.entity.children[0],
        DNSName("test.com"),
        EntityTag.new("test-tag"),
        IPADDRESS,
        [device.entity, services.entity.children[0]]
    )

    new_name_event = _get_deserialized_object(name_event, setup.get_system())
    assert new_name_event == name_event
