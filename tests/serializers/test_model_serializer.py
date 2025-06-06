from unittest.mock import patch, MagicMock
from ipaddress import ip_network

from toolsaf.main import HTTP, BLEAdvertisement
from toolsaf.common.address import EntityTag, DNSName, HWAddress, Network
from toolsaf.common.basics import Status
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
from tests.test_model_new import Setup_1
from tests.test_model import Setup


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
    service = device.broadcast(BLEAdvertisement(event_type=0x03)).entity
    serialized = list(stream.write(service))[0]
    assert serialized == {
        "type": "service",
        "id": "id1",
        "name": "BLE Ad:3 multicast",
        "authentication": False,
        "client_side": False,
        "reply_from_other_address": False,
        "protocol": "ble",
        "con_type": "",
        "multicast_source": "BLE_Ad"
    }
    serialized["type"] = "service"

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
    assert new_service.multicast_source == EntityTag("BLE_Ad")

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
        "status": Status.EXPECTED.value
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
    assert [j["type"] for j in js] == ["system", "host", "service", "sw", "host", "sw", "network", "connection", "online-resource"]

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
        "upload_tag": "_",
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
    assert len(r) == 9
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