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
from toolsaf.core.model import IoTSystem, EvidenceNetworkSource
from toolsaf.core.services import NameEvent
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.verdict import Verdict
from tests.test_model import Setup


SOURCE = EvidenceSource(name="Test", base_ref="../test.json")
HWADDRESS = HWAddress.new("00:00:00:00:00:00")
IPADDRESS = IPAddress.new("1.1.1.1")
SYSTEM = Setup().get_system()

T = TypeVar("T")


def _get_serialized_event(event, system: IoTSystem = IoTSystem()):
    serializer = EventSerializer(system)
    return serializer.serialize(event)[-1]


def _get_deserialized_object(obj: T, system: IoTSystem = SYSTEM) -> T:
    serializer = EventSerializer(system)
    records = serializer.serialize(obj)
    return [serializer.deserialize(record) for record in records][-1]


def test_event_source():
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

    new_flow = _get_deserialized_object(EthernetFlow(Evidence(source1), source=HWADDRESS, target=HWADDRESS))
    new_source = new_flow.evidence.source
    assert new_source.name == source1.name
    assert new_source.base_ref == "test1.json"
    assert new_source.label == source1.label
    assert new_source.timestamp == source1.timestamp
    assert new_source.target == source1.target


def test_event_source_address_map():
    setup = Setup()
    device = setup.system.device("Test Device")
    system = setup.get_system()

    source = EvidenceNetworkSource(name="MapSource", base_ref="../test.json", label="test-label")
    ip_addr = IPAddress.new("192.168.1.1")
    source.address_map[ip_addr] = device.entity

    flow = EthernetFlow(Evidence(source), source=HWADDRESS, target=HWADDRESS)
    serializer = EventSerializer(system)
    records = serializer.serialize(flow)
    source_dict = records[0]

    assert "address_map" in source_dict
    assert len(source_dict["address_map"]) == 1
    assert source_dict["address_map"][0]["address"] == "192.168.1.1"
    assert source_dict["address_map"][0]["entity"] == "Test_Device"

    new_flow = [serializer.deserialize(record) for record in records][-1]
    new_source = new_flow.evidence.source
    assert ip_addr in new_source.address_map
    assert new_source.address_map[ip_addr] == device.entity


def test_ethernet_flow():
    ethernet_flow = EthernetFlow(
        Evidence(SOURCE, tail_ref=":12"),
        source=HWADDRESS,
        target=HWADDRESS,
        payload=5
    )
    ethernet_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    ethernet_flow.properties = {
        PropertyKey("eth-key"): PropertyVerdictValue(Verdict.PASS, "eth test")
    }

    assert _get_serialized_event(ethernet_flow) == {
        "type": "ethernet-flow",
        "source_id": "id1",
        "source": "00:00:00:00:00:00|hw",
        "target": "00:00:00:00:00:00|hw",
        "protocol": "eth",
        "payload": 5,
        "timestamp": "2025-01-01T00:00:00+00:00",
        "tail_ref": ":12",
        "properties": {"eth-key": {"verdict": "Pass", "exp": "eth test"}}
    }

    new_ethernet_flow = _get_deserialized_object(ethernet_flow)
    assert new_ethernet_flow.source == HWADDRESS
    assert new_ethernet_flow.target == HWADDRESS
    assert new_ethernet_flow.payload == 5
    assert new_ethernet_flow.protocol == Protocol.ETHERNET
    assert new_ethernet_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert new_ethernet_flow.evidence.source.name == "Test"
    assert new_ethernet_flow.evidence.tail_ref == ":12"
    assert new_ethernet_flow.properties[PropertyKey("eth-key")] == PropertyVerdictValue(Verdict.PASS, "eth test")


def test_ip_flow():
    ip_flow = IPFlow(Evidence(SOURCE, tail_ref=""),
        source=(HWADDRESS, IPADDRESS, 10),
        target=(HWADDRESS, IPADDRESS, 11),
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
        "target": ["00:00:00:00:00:00|hw", "1.1.1.1", 11],
        "protocol": "tcp",
        "timestamp": "2025-01-01T00:00:00+00:00",
        "tail_ref": ""
    }

    new_ip_flow = _get_deserialized_object(ip_flow)
    assert new_ip_flow.evidence.tail_ref == ""
    assert new_ip_flow.source == (HWADDRESS, IPADDRESS, 10)
    assert new_ip_flow.target == (HWADDRESS, IPADDRESS, 11)
    assert new_ip_flow.protocol == Protocol.TCP
    assert new_ip_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert new_ip_flow.evidence.source.name == "Test"
    assert new_ip_flow.properties[PropertyKey("test-key")] == PropertyVerdictValue(Verdict.PASS, "test")
    assert new_ip_flow.properties[PropertyKey("test-key2")] == PropertySetValue({PropertyKey("1"), PropertyKey("2")}, "test2")


def test_ble_advertisement_flow():
    ble_flow = BLEAdvertisementFlow(
        Evidence(SOURCE, tail_ref=":34"),
        source=HWADDRESS,
        event_type=0x03
    )
    ble_flow.timestamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    ble_flow.properties = {
        PropertyKey("ble-key"): PropertyVerdictValue(Verdict.PASS, "ble test")
    }

    assert _get_serialized_event(ble_flow) == {
        "type": "ble-advertisement-flow",
        "source_id": "id1",
        "source": "00:00:00:00:00:00|hw",
        "protocol": "ble",
        "event_type": 3,
        "timestamp": "2025-01-01T00:00:00+00:00",
        "tail_ref": ":34",
        "properties": {"ble-key": {"verdict": "Pass", "exp": "ble test"}}
    }

    new_ble_flow = _get_deserialized_object(ble_flow)
    assert new_ble_flow.source == HWADDRESS
    assert new_ble_flow.event_type == 0x03
    assert new_ble_flow.protocol == ble_flow.protocol
    assert new_ble_flow.timestamp == datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert new_ble_flow.evidence.source.name == "Test"
    assert new_ble_flow.evidence.tail_ref == ":34"
    assert new_ble_flow.properties[PropertyKey("ble-key")] == PropertyVerdictValue(Verdict.PASS, "ble test")


def test_service_scan():
    service_scan = ServiceScan(
        Evidence(SOURCE, tail_ref=":56"),
        EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000),
        service_name="test-name"
    )

    assert _get_serialized_event(service_scan) == {
        "type": "service-scan",
        "source_id": "id1",
        "service_name": "test-name",
        "address": "127.0.0.1/tcp:8000",
        "tail_ref": ":56"
    }

    new_service_scan = _get_deserialized_object(service_scan)
    assert new_service_scan.endpoint == EndpointAddress.ip("127.0.0.1", Protocol.TCP, 8000)
    assert new_service_scan.service_name == "test-name"
    assert new_service_scan.evidence.source.name == "Test"
    assert new_service_scan.evidence.source.base_ref == "test.json"
    assert new_service_scan.evidence.tail_ref == ":56"


def test_host_scan():
    endpoints = [
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8000),
        EndpointAddress.ip("1.1.1.2", Protocol.TCP, 8002),
    ]
    host_scan = HostScan(
        Evidence(SOURCE, tail_ref=":78"), IPADDRESS, endpoints=endpoints
    )

    assert _get_serialized_event(host_scan) == {
        "type": "host-scan",
        "source_id": "id1",
        "host": "1.1.1.1",
        "endpoints": ["1.1.1.2/tcp:8000", "1.1.1.2/tcp:8002"],
        "tail_ref": ":78"
    }

    new_host_scan = _get_deserialized_object(host_scan)
    assert new_host_scan.host == IPADDRESS
    assert endpoints[0] in new_host_scan.endpoints
    assert endpoints[1] in new_host_scan.endpoints
    assert new_host_scan.evidence.source.name == "Test"
    assert new_host_scan.evidence.source.base_ref == "test.json"
    assert new_host_scan.evidence.tail_ref == ":78"


def test_property_address_event():
    # PropertyVerdictValue
    event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey.parse("test-key:abc").verdict(Verdict.PASS, "test explanation")
    )
    assert _get_serialized_event(event) == {
        "type": "property-address-event",
        "source_id": "id1",
        "address": "1.1.1.1",
        "key": "test-key:abc",
        "value": {"verdict": "Pass", "explanation": "test explanation"}
    }
    new_event = _get_deserialized_object(event)
    assert new_event.address == IPADDRESS
    assert new_event.key_value == PropertyKey.parse("test-key:abc").verdict(Verdict.PASS, "test explanation")
    assert new_event.evidence.source.name == "Test"

    # PropertySetValue
    event = PropertyAddressEvent(
        Evidence(SOURCE), IPADDRESS,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    serialized = _get_serialized_event(event)
    assert "value-key" in serialized["value"]["sub_keys"]
    assert "key-value" in serialized["value"]["sub_keys"]
    assert serialized["value"]["explanation"] == ""
    new_event = _get_deserialized_object(event)
    assert new_event.address == IPADDRESS
    assert new_event.key_value == PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})


def test_property_event():
    setup = Setup()
    system = setup.get_system()
    software = setup.system.device("Test Device").software("Test Software").sw

    # PropertyVerdictValue
    event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey.parse("test-key:abc").verdict(Verdict.PASS, "test explanation")
    )
    assert _get_serialized_event(event) == {
        "type": "property-event",
        "source_id": "id1",
        "address": "Test_Device&software=Test_Software",
        "key": "test-key:abc",
        "value": {"verdict": "Pass", "explanation": "test explanation"}
    }
    new_event = _get_deserialized_object(event, system)
    assert event.entity == new_event.entity
    assert event.key_value == new_event.key_value

    # PropertySetValue
    event = PropertyEvent(
        Evidence(SOURCE), software,
        PropertyKey("test-key").value_set({PropertyKey("value-key"), PropertyKey("key-value")})
    )
    serialized = _get_serialized_event(event)
    assert "value-key" in serialized["value"]["sub_keys"]
    assert "key-value" in serialized["value"]["sub_keys"]
    new_event = _get_deserialized_object(event, system)
    assert event.entity == new_event.entity
    assert event.key_value == new_event.key_value

    # IoTSystem root entity (address == "")
    event = PropertyEvent(
        Evidence(SOURCE), SYSTEM,
        PropertyKey("system-key").verdict(Verdict.PASS, "system explanation")
    )
    assert _get_serialized_event(event, SYSTEM) == {
        "type": "property-event",
        "source_id": "id1",
        "address": "",
        "key": "system-key",
        "value": {"verdict": "Pass", "explanation": "system explanation"}
    }
    new_event = _get_deserialized_object(event, SYSTEM)
    assert new_event.entity is SYSTEM
    assert new_event.key_value == event.key_value


def test_name_event():
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
        [device.entity, services.entity.children[0]],
        timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    )

    assert _get_serialized_event(name_event) == {
        "type": "name-event",
        "source_id": "id1",
        "name": "test.com",
        "peers": ["Test_Device", "Services/udp:53"],
        "service": "Services/udp:53",
        "tag": "test-tag",
        "address": "1.1.1.1",
        "timestamp": "2025-01-01T00:00:00+00:00"
    }

    new_name_event = _get_deserialized_object(name_event, setup.get_system())
    assert new_name_event.service == name_event.service
    assert new_name_event.name == name_event.name
    assert new_name_event.address == name_event.address
    assert new_name_event.tag == name_event.tag
    assert set(new_name_event.peers) == set(name_event.peers)
    assert new_name_event.timestamp == name_event.timestamp
