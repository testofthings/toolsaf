from toolsaf.main import HTTP
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.components import Software
from toolsaf.core.model import Connection, IoTSystem
from toolsaf.core.serializer.model_serializers import IoTSystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    su.system.online_resource("test-policy", url="example-url", keywords=["test", "policy"])
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
    }

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
    }

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
    }

    assert js[3] == {
        "id": "id4",
        "at": "id2",
        "type": "sw",
        "name": "Device 1 SW",
        "long_name": "Device 1 SW",
        "address": "Device&software=Device_1_SW",
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
    assert r[0].children[0] == r[1]
    assert len(r[0].children[0].children) == 1
    assert r[0].children[0].children[0].name == "SSH:22"
    assert r[0].children[1] == r[4]
    assert isinstance(r[7], Connection)
    assert r[7].source == r[4]
    assert r[7].target == r[2]
    assert isinstance(r[3], Software)
