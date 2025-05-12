from unittest.mock import patch, MagicMock

from toolsaf.main import HTTP
from toolsaf.common.basics import Status, ConnectionType
from toolsaf.common.verdict import Verdict
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.components import Software, SoftwareComponent
from toolsaf.core.model import Connection, IoTSystem, NodeComponent
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.core.serializer.model_serializers import (
    IoTSystemSerializer, ConnectionSerializer, NodeComponentSerializer, SoftwareSerializer
)
from tests.test_model_new import Setup_1
from tests.test_model import Setup


def test_connection_serializer():
    serializer = ConnectionSerializer()
    stream = SerializerStream(serializer)

    device1 = Setup().system.device("Device 1")
    device2 = Setup().system.device("Device 2")
    connection = (device1 >> device2 / HTTP).connection

    stream.context.identifier_map[device1.entity] = "Device 1"
    stream.context.identifier_map[(device2 / HTTP).entity] = "Device 2 HTTP:80"
    stream.context.object_map["Device 1"] = device1.entity
    stream.context.object_map["Device 2 HTTP:80"] = (device2 / HTTP).entity

    serializer.write(connection, stream)
    assert stream.data == {
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

    new_connection = serializer.new(stream)
    serializer.read(new_connection, stream)

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
        "tag": "_",
        "upload_tag": "_",
        "properties": {},
    }

    ignore_name_reqs = js[1].pop("ignore_name_requests")
    assert "time.test.com" in ignore_name_reqs and "time.test2.com" in ignore_name_reqs
    assert js[1] == {
        'address': 'Device',
        'addresses': ['10:00:00:00:00:01|hw'],
        'host_type': 'Device',
        'at': 'id1',
        'id': 'id2',
        'long_name': 'Device 1',
        'name': 'Device 1',
        'status': 'Expected',
        'tag': 'Device',
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
        "tag": "Device/tcp:22",
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
        #"type": "IPv4",
        "address": "192.168.0.0/16",
        #"hostmask": "0.0.255.255",
        #"is_multicast": False,
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
