from unittest.mock import patch, MagicMock
from ipaddress import ip_network

from toolsaf.core.address_ranges import AddressRange, MulticastTarget
from toolsaf.main import HTTP, UDP, BLEAdvertisement, DHCP, DNS
from toolsaf.common.address import Addresses, EntityTag, DNSName, HWAddress, Network, Protocol
from toolsaf.common.basics import Status, ExternalActivity, HostType, ConnectionType
from toolsaf.common.verdict import Verdict
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.components import Software, SoftwareComponent
from toolsaf.core.online_resources import OnlineResource
from toolsaf.core.model import (
    IoTSystem,
    Connection, NodeComponent, Service, Host, Addressable
)
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.core.serializer.model_serializers import (
    IoTSystemSerializer, OnlineResourceSerializer,
    NetworkSerializer, AddressableSerializer, HostSerializer,
    ServiceSerializer, ConnectionSerializer, NodeComponentSerializer, SoftwareSerializer
)
from toolsaf.core.services import DHCPService, DNSService
from tests.test_model_new import Setup_1
from tests.test_model import Setup

from toolsaf.core.serializer.pydantic_models import SystemSerializer


def test_online_resource_serializer():
    serializer = OnlineResourceSerializer()
    serializer.config.map_class("online-resource", serializer)
    stream = SerializerStream(serializer)
    mock_resolve = MagicMock()
    stream.resolve = mock_resolve

    mock_parent = MagicMock()
    mock_parent.online_resources = []
    mock_resolve.return_value = mock_parent

    online_resource = OnlineResource(
        "test-policy", url="example-url",
        keywords=["test"]
    )

    serialized = list(stream.write(online_resource))[0]
    assert serialized == {
        "id": "id1",
        "type": "online-resource",
        "name": "test-policy",
        "url": "example-url",
        "keywords": ["test"]
    }

    new_online_resource = list(stream.read([serialized]))[0]
    assert isinstance(new_online_resource, OnlineResource)
    assert new_online_resource.name == online_resource.name
    assert new_online_resource.url == online_resource.url
    assert new_online_resource.keywords == online_resource.keywords
    assert new_online_resource in mock_parent.online_resources


def test_network_serializer():
    serializer = NetworkSerializer()
    serializer.config.map_class("network", serializer)
    stream = SerializerStream(serializer)
    mock_resolve = MagicMock()
    stream.resolve = mock_resolve

    setup = Setup()
    device = setup.system.device("Device 1")
    network = Network("test-network", ip_network("127.0.0.1"))
    device.entity.networks.append(network)

    serialized = list(stream.write(network))[0]
    assert serialized == {
        "id": "id1",
        "type": "network",
        "name": "test-network",
        "address": "127.0.0.1/32"
    }

    mock_resolve.return_value = device.entity
    new_network = list(stream.read([serialized]))[0]
    assert isinstance(new_network, Network)
    assert new_network.name == network.name
    assert new_network.ip_network == network.ip_network
    assert new_network in device.entity.networks


def test_addressable_serializer():
    serializer = AddressableSerializer()
    stream = SerializerStream(serializer)
    mock_resolve = MagicMock()
    stream.resolve = mock_resolve

    setup = Setup()
    device = setup.system.device("Device 1")
    addressable = device.entity

    addressable.addresses.add(EntityTag("Device_1"))
    addressable.addresses.add(HWAddress.new("10:00:00:00:00:01"))
    addressable.any_host = True

    serializer.write(addressable, stream)
    serialized = stream.data

    assert serialized == {
        "addresses": ["Device_1", "10:00:00:00:00:01|hw"],
        "any_host": True
    }

    stream.resolve.return_value = setup.get_system()
    new_addressable = Addressable("", MagicMock())
    serializer.read(new_addressable, stream)

    assert new_addressable.addresses == addressable.addresses
    assert new_addressable.any_host is True
    assert new_addressable in setup.get_system().children


def test_host_serializer():
    serializer = HostSerializer()
    serializer.config.map_class("host", serializer)
    stream = SerializerStream(serializer)
    mock_resolve = MagicMock()
    stream.resolve = mock_resolve

    setup = Setup()
    device = setup.system.device("Device 1")
    host = device.entity
    host.ignore_name_requests.add(DNSName("test.com"))
    host.ignore_name_requests.add(DNSName("test2.com"))

    serialized = list(stream.write(host))[0]
    assert serialized["id"] == "id1"
    assert serialized["type"] == "host"
    assert "test.com" in serialized["ignore_name_requests"]
    assert "test2.com" in serialized["ignore_name_requests"]

    # name is not included in the serialized data, but it is needed in deserialization
    serialized["name"] = host.name

    stream.resolve.return_value = setup.get_system()
    new_host = list(stream.read([serialized]))[0]

    assert isinstance(new_host, Host)
    assert new_host.name == host.name
    assert new_host.ignore_name_requests == host.ignore_name_requests


def test_service_serializer():
    serializer = ServiceSerializer()
    serializer.config.map_class("service", serializer)
    stream = SerializerStream(serializer)
    mock_resolve = MagicMock()
    stream.resolve = mock_resolve

    device = Setup().system.device("Device 1")
    service = (device / BLEAdvertisement(event_type=0x03)).entity
    serialized = list(stream.write(service))[0]
    assert serialized == {
        "type": "service",
        "id": "id1",
        "name": "BLE Ad:3",
        "authentication": False,
        "client_side": False,
        "reply_from_other_address": False,
        "protocol": "ble",
        "con_type": "",
        "multicast_target": "BLE_Ad|hw"
    }

    stream.resolve.return_value = device.entity
    new_service = list(stream.read([serialized]))[0]

    assert isinstance(new_service, Service)
    assert new_service.parent == device.entity
    assert new_service.name == service.name
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.multicast_target == MulticastTarget(fixed_address=Addresses.BLE_Ad)
    assert new_service.port_range is None

    stream = SerializerStream(serializer)
    service = (device / HTTP).entity
    stream.resolve = mock_resolve

    serialized = list(stream.write(service))[0]
    assert serialized == {
        "type": "service",
        "id": "id1",
        "name": "HTTP:80",
        "authentication": False,
        "client_side": False,
        "reply_from_other_address": False,
        "protocol": "http",
        "con_type": "",
    }

    stream.resolve.return_value = device.entity
    new_service = list(stream.read([serialized]))[0]

    assert isinstance(new_service, Service)
    assert new_service.name == service.name
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type


def test_service_with_multicast_target_serializer():
    serializer = ServiceSerializer()
    serializer.config.map_class("service", serializer)
    stream = SerializerStream(serializer)
    mock_resolve = MagicMock()
    stream.resolve = mock_resolve

    device = Setup().system.device("Device 1")
    service = (device / UDP(port=987).multicast("224.0.*.*")).entity
    serialized = list(stream.write(service))[0]
    assert serialized == {
        "type": "service",
        "id": "id1",
        "name": "UDP:987 224.0.*.*",
        "authentication": False,
        "client_side": False,
        "reply_from_other_address": False,
        "protocol": "",
        "con_type": "",
        "multicast_target": "224.0.*.*"
    }


    stream.resolve.return_value = device.entity
    new_service = list(stream.read([serialized]))[0]

    assert isinstance(new_service, Service)
    assert new_service.parent == device.entity
    assert new_service.name == service.name
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.protocol is None  # NOTE: Not Any now
    assert new_service.con_type == service.con_type
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range is None

    # add test with port range, too

    service = (device / UDP().port_range(1000, 2000).multicast("224.0.0.1")).entity
    serialized = list(stream.write(service))[0]
    assert serialized == {
        "type": "service",
        "id": "id3",
        "name": "UDP:1000-2000 224.0.0.1",
        "authentication": False,
        "client_side": False,
        "reply_from_other_address": False,
        "protocol": "",
        "con_type": "",
        "multicast_target": "224.0.0.1",
        "port_range": "1000-2000",
    }


    stream.resolve.return_value = device.entity
    new_service = list(stream.read([serialized]))[0]

    assert isinstance(new_service, Service)
    assert new_service.parent == device.entity
    assert new_service.name == service.name
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.protocol is None  # NOTE: Not Any now
    assert new_service.con_type == service.con_type
    assert new_service.multicast_target == MulticastTarget(fixed_address=Addresses.parse_address("224.0.0.1"))
    assert new_service.port_range == service.port_range


def test_iot_system_dto():
    setup = Setup()
    setup.system.system.name = "Test System"
    setup.system.system.description = "desc"
    setup.system.tag("test-tag")
    device = setup.system.device("Device 1")
    setup.system.ignore("pcap-0").at(device).properties("verdict:key", "verdict:key2").because("exp1")
    setup.system.ignore("pcap-1").properties("verdict:key3").because("exp2")
    setup.system.system.ignore_rules = setup.system.ignore_backend.get_rules()

    serialized = SystemSerializer().serialize(setup.system.system)
    ignore_rules = serialized.pop("ignore_rules")
    assert serialized == {
        "name": "Test System",
        "description": "desc",
        "match_priority": 0,
        "system_address": "",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "expected": None,
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.BANNED.value,
        "properties": {},
        "type": "system",
        "upload_tag": "test-tag"
    }
    assert "pcap-0" in ignore_rules["rules"] and "pcap-1" in ignore_rules["rules"]
    assert len(ignore_rules["rules"]["pcap-0"]) == 1
    assert len(ignore_rules["rules"]["pcap-1"]) == 1
    assert ignore_rules["rules"]["pcap-0"][0]["at"] == ["Device_1"]
    assert ignore_rules["rules"]["pcap-0"][0]["explanation"] == "exp1"
    assert sorted(ignore_rules["rules"]["pcap-0"][0]["properties"]) == ["verdict:key", "verdict:key2"]
    assert ignore_rules["rules"]["pcap-1"][0]["at"] == []
    assert ignore_rules["rules"]["pcap-1"][0]["explanation"] == "exp2"
    assert ignore_rules["rules"]["pcap-1"][0]["properties"] == ["verdict:key3"]

    iot_system = SystemSerializer().deserialize(serialized | {"ignore_rules": ignore_rules})
    assert isinstance(iot_system, IoTSystem)
    assert iot_system.name == setup.system.system.name
    assert iot_system.upload_tag == setup.system.system.upload_tag
    assert setup.system.system.ignore_rules == iot_system.ignore_rules


def test_host_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    host = device.entity
    host.ignore_name_requests.add(DNSName("test.com"))
    host.ignore_name_requests.add(DNSName("test2.com"))

    serializer = SystemSerializer()
    s_system = serializer.serialize(setup.system.system)
    s_host = serializer.serialize(host)
    ignore_name_reqs = s_host.pop("ignore_name_requests")
    assert s_host == {
        "name": "Device 1",
        "description": "Internet Of Things device",
        "match_priority": 10,
        "system_address": "Device_1",
        "host_type": HostType.DEVICE.value,
        "status": "Expected",
        "expected": None,
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.PASSIVE.value,
        "properties": {},
        "addresses": ["Device_1"],
        "parent": "",
        "any_host": False,
        "type": "host"
    }
    assert sorted(ignore_name_reqs) == ["test.com", "test2.com"]

    new_system = serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host | {"ignore_name_requests": ignore_name_reqs})
    assert isinstance(new_host, Host)
    assert new_host.name == host.name
    assert new_host.ignore_name_requests == host.ignore_name_requests
    assert new_host.parent == new_system
    assert new_host in new_system.children


def test_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / HTTP).entity

    serializer = SystemSerializer()
    s_system = serializer.serialize(setup.system.system)
    s_host = serializer.serialize(setup.system.device("Device 1").entity)
    s_service = serializer.serialize(service)
    assert s_service == {
        "name": "HTTP:80",
        "description": "",
        "match_priority": 10,
        "system_address": "Device_1/tcp:80",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "expected": None,
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.PASSIVE.value,
        "properties": {},
        "addresses": ["*/tcp:80"],
        "parent": "Device_1",
        "any_host": False,
        "type": "service",
        "protocol": Protocol.HTTP.value,
        "con_type": ConnectionType.UNKNOWN.value,
        "authentication": False,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": False
    }
    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_service = serializer.deserialize(s_service)

    assert isinstance(new_service, Service)
    assert new_service.name == service.name
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host


def test_dhcp_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DHCP).entity

    serializer = SystemSerializer()
    s_system = serializer.serialize(setup.system.system)
    s_host = serializer.serialize(device.entity)
    s_service = serializer.serialize(service)

    assert s_service == {
        "name": "DHCP",
        "description": "DHCP service",
        "match_priority": 10,
        "system_address": "Device_1/udp:67",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "expected": None,
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.UNLIMITED.value,
        "properties": {},
        "addresses": ["*/udp:67"],
        "parent": "Device_1",
        "any_host": False,
        "type": "dhcp-service",
        "protocol": None,
        "con_type": ConnectionType.ADMINISTRATIVE.value,
        "authentication": False,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": True
    }

    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_service = serializer.deserialize(s_service)

    assert isinstance(new_service, DHCPService)
    assert new_service.name == service.name
    assert new_service.description == service.description
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host


def test_dns_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DNS).entity

    serializer = SystemSerializer()
    s_system = serializer.serialize(setup.system.system)
    s_host = serializer.serialize(device.entity)
    s_service = serializer.serialize(service)

    assert s_service == {
        "name": "DNS",
        "description": "",
        "match_priority": 10,
        "system_address": "Device_1/udp:53",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "expected": None,
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.OPEN.value,
        "properties": {},
        "addresses": ["*/udp:53"],
        "parent": "Device_1",
        "any_host": False,
        "type": "dns-service",
        "protocol": None,
        "con_type": ConnectionType.ADMINISTRATIVE.value,
        "authentication": False,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": False
    }

    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_service = serializer.deserialize(s_service)

    assert isinstance(new_service, DNSService)
    assert new_service.name == service.name
    assert new_service.description == service.description
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host


def test_software_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    software = device.software("Test Software").sw
    software.components = {
        "tc": SoftwareComponent("test-component", "1.0"),
        "tc2": SoftwareComponent("test-component2", "2.0"),
    }
    software.permissions.add("permission1")

    serializer = SystemSerializer()
    s_system = serializer.serialize(setup.system.system)
    s_host = serializer.serialize(device.entity)
    s_software = serializer.serialize(software)

    assert s_software == {
        "name": "Test Software",
        "system_address": "Device_1&software=Test_Software",
        "status": "Expected",
        "parent": "Device_1",
        "type": "software",
        "components": [
            {"key": "tc", "name": "test-component", "version": "1.0"},
            {"key": "tc2", "name": "test-component2", "version": "2.0"},
        ],
        "permissions": ["permission1"]
    }

    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_software = serializer.deserialize(s_software)

    assert isinstance(new_software, Software)
    assert new_software.name == software.name
    assert new_software.components == software.components
    assert new_software.permissions == software.permissions
    assert new_software.entity == new_host


def test_connection_dto():
    device1 = Setup().system.device("Device 1")
    device2 = Setup().system.device("Device 2")
    connection = (device1 >> device2 / HTTP).connection

    assert SystemSerializer().serialize(connection) == {
        "type": "connection",
        "system_address": "source=Device_1&target=Device_2/tcp:80",
        "source_system_address": "Device_1",
        "target_system_address": "Device_2/tcp:80",
        "con_type": ConnectionType.UNKNOWN.value,
        "status": "Expected",
        "properties": {},
    }


def test_connection_serializer():
    serializer = ConnectionSerializer()
    serializer.config.map_class("connection", serializer)
    stream = SerializerStream(serializer)

    device1 = Setup().system.device("Device 1")
    device2 = Setup().system.device("Device 2")
    connection = (device1 >> device2 / HTTP).connection

    stream.context.identifier_map[device1.entity] = "Device 1"
    stream.context.identifier_map[(device2 / HTTP).entity] = "Device 2 HTTP:80"
    stream.context.object_map["Device 1"] = device1.entity
    stream.context.object_map["Device 2 HTTP:80"] = (device2 / HTTP).entity

    serialized = list(stream.write(connection))[0]
    assert serialized == {
        "type": "connection",
        "id": "id3", # 3 due to earlier identifier_map modifications
        "address": "source=Device_1&target=Device_2/tcp:80",
        "source": "Device 1",
        "target": "Device 2 HTTP:80",
        "source_long_name": "Device 1",
        "target_long_name": "Device 2 HTTP:80",
        "tag": "Device_1--Device_2/tcp:80",
        "name": "HTTP:80",
        "long_name": "Device 1 => Device 2 HTTP:80",
        "status": Status.EXPECTED
    }

    new_connection = list(stream.read([serialized]))[0]
    assert isinstance(new_connection, Connection)
    assert new_connection.source == connection.source
    assert new_connection.target == connection.target
    assert new_connection.status == connection.status


def test_node_component_serializer():
    serializer = NodeComponentSerializer()
    stream = SerializerStream(serializer)
    device = Setup().system.device("TestDevice")
    node_component = NodeComponent(device.entity, "test-component")
    node_component.status = Status.EXTERNAL

    serializer.write(node_component, stream)
    assert stream.data == {
        "status": Status.EXTERNAL.value,
        "address": "TestDevice&other=test-component",
        "long_name": "test-component"
    }

    # FIXME: Should include read / new?
    # new_component = serializer.read(stream)


def test_software_serializer():
    serializer = SoftwareSerializer()
    stream = SerializerStream(serializer)
    software = Software("test-software", "test-software")
    software.components = {
        "tc": SoftwareComponent("test-component", "1.0"),
        "tc2": SoftwareComponent("test-component2", "2.0"),
    }
    serializer.write(software, stream)

    assert stream.data == {
        "components": [
            {"key": "tc", "component-name": "test-component", "version": "1.0"},
            {"key": "tc2", "component-name": "test-component2", "version": "2.0"},
        ]
    }

    mock_resolve = MagicMock()
    mock_parent = MagicMock()
    mock_resolve.return_value = mock_parent
    stream.resolve = mock_resolve

    # Add fields that would come from other serializers
    stream.data["name"] = "test-software"

    new_software = serializer.new(stream)
    serializer.read(new_software, stream)
    assert new_software.name == software.name
    assert new_software.components == software.components


def test_serialize_network_node_properties():
    setup = Setup()
    setup.get_system().name = "Test System"
    device = setup.system.device("Device 1")

    device.set_property("default", "sensors")
    device.entity.properties[
        PropertyKey.create(("verdict", "key"))
    ] = PropertyVerdictValue(Verdict.PASS, "Test explanation")
    device.entity.properties[
        PropertyKey.create(("set", "key"))
    ] = PropertySetValue(
        {PropertyKey.create(("test", "key1")), PropertyKey.create(("test", "key2"))},
        "Test explanation",
    )

    serializer = IoTSystemSerializer(setup.get_system())
    stream = SerializerStream(serializer)
    serialized = list(stream.write(serializer.system))

    ser = IoTSystemSerializer(IoTSystem())
    stream = SerializerStream(ser)
    deserialized = list(stream.read(serialized))

    assert deserialized[0].properties == setup.get_system().properties
    assert deserialized[1].properties == device.entity.properties


def test_simple_model():
    su = Setup_1()
    su.system.online_resource("test-policy", url="example-url", keywords=["test", "policy"])
    su.device1.software().sbom(components=["c1", "c2"])
    su.device1.ignore_name_requests("time.test.com", "time.test2.com")
    su.system.finish_()  # creates SW components
    su.system.system.name = "Test"
    ser = IoTSystemSerializer(su.system.system)
    stream = SerializerStream(ser)
    js = list(stream.write(ser.system))
    assert [j["type"] for j in js] == ["system", "host", "service", "sw", "host", "sw", "network", "connection", "online-resource", "ignore-rules"]

    assert js[0] == {
        "id": "id1",
        "type": "system",
        "name": "Test",
        "long_name": "Test",
        "description": "",
        "match_priority": 0,
        "address": "",
        "host_type": "",
        "status": "Expected",
        "upload_tag": "test-system",
        "properties": {},
    }

    ignore_name_reqs = js[1].pop("ignore_name_requests")
    assert "time.test.com" in ignore_name_reqs and "time.test2.com" in ignore_name_reqs
    assert js[1] == {
        'address': 'Device',
        'addresses': ['Device', '10:00:00:00:00:01|hw'],
        'host_type': 'Device',
        'at': 'id1',
        'id': 'id2',
        'long_name': 'Device 1',
        'name': 'Device 1',
        'status': 'Expected',
        'type': 'host',
        "description": "Internet Of Things device",
        "match_priority": 10,
        "properties": {},
    }
    js[1]["ignore_name_requests"] = ["time.test.com", "time.test2.com"]

    assert js[2] == {
        "id": "id3",
        "at": "id2",
        "type": "service",
        "name": "SSH:22",
        "long_name": "Device 1 SSH:22",
        "description": "",
        "match_priority": 10,
        "address": "Device/tcp:22",
        "host_type": "",
        "status": "Expected",
        "addresses": ["*/tcp:22"],
        "properties": {},
        "authentication": True,
        "client_side": False,
        "con_type": "Encrypted",
        "protocol": "ssh",
        "reply_from_other_address": False
    }

    assert js[3] == {
        "id": "id4",
        "at": "id2",
        "type": "sw",
        "name": "Device 1 SW",
        "long_name": "Device 1 SW",
        "address": "Device&software=Device_1_SW",
        "status": "Expected",
        "components": [
            {"key": "c1", "component-name": "c1", "version": ""},
            {"key": "c2", "component-name": "c2", "version": ""},
        ]
    }

    assert js[6] == {
        "id": "id7",
        "at": "id1",
        "type": "network",
        "name": "local",
        "address": "192.168.0.0/16",
    }

    assert js[7] == {
        'address': 'source=Device_2&target=Device/tcp:22',
        'id': 'id8',
        'at': 'id1',
        'long_name': 'some.local => Device 1 SSH:22',
        'name': 'SSH:22',
        'type': 'connection',
        'source': 'id5',
        'source_long_name': 'some.local',
        'tag': 'Device_2--Device/tcp:22',
        'target': 'id3',
        'target_long_name': 'Device 1 SSH:22',
        'status': 'Expected',
    }

    assert js[8] == {
        "id": "id9",
        "at": "id1",
        "type": "online-resource",
        "name": "test-policy",
        "url": "example-url",
        "keywords": ["test", "policy"],
    }

    ser = IoTSystemSerializer(IoTSystem())
    stream = SerializerStream(ser)
    r = list(stream.read(js))
    assert len(r) == 10
    assert isinstance(r[0], IoTSystem)
    assert len(r[0].online_resources) == 1
    assert len(r[0].networks) == 1
    assert r[0].name == "Test"
    assert len(r[0].children) == 2
    assert r[0].children[0].name == "Device 1"
    assert len(r[1].components) == 1
    assert len(r[1].components[0].components) == 2
    assert len(r[1].ignore_name_requests) == 2
    assert r[0].children[0] == r[1]
    assert len(r[0].children[0].children) == 1
    assert r[0].children[0].children[0].name == "SSH:22"
    assert r[0].children[1] == r[4]
    assert isinstance(r[7], Connection)
    assert r[7].source == r[4]
    assert r[7].target == r[2]
    assert isinstance(r[3], Software)
    assert r[7] in r[1].connections
    assert r[7] in r[4].connections