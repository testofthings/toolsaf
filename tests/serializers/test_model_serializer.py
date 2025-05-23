from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.components import Software
from toolsaf.core.model import Connection, IoTSystem
from toolsaf.core.serializer.model_serializers import IoTSystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    su.system.finish_()  # creates SW components
    su.system.system.name = "Test"
    ser = IoTSystemSerializer(su.system.system)
    stream = SerializerStream(ser)
    js = list(stream.write(ser.system))
    assert [j["type"] for j in js] == ["system", "host", "service", "sw", "host", "sw", "connection"]
    assert js[0].items() >= {'id': 'id1', 'type': 'system', 'name': 'Test'}.items()
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
    }
    assert js[3].items() >= {'id': 'id4', 'at': 'id2', 'type': 'sw', 'name': 'Device 1 SW'}.items()
    assert js[6] == {
        'address': 'source=Device_2&target=Device/tcp:22',
        'id': 'id7',
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

    ser = IoTSystemSerializer(IoTSystem())
    stream = SerializerStream(ser)
    r = list(stream.read(js))
    assert len(r) == 7
    assert isinstance(r[0], IoTSystem)
    assert r[0].name == "Test"
    assert len(r[0].children) == 2
    assert r[0].children[0].name == "Device 1"
    assert r[0].children[0] == r[1]
    assert len(r[0].children[0].children) == 1
    assert r[0].children[0].children[0].name == "SSH:22"
    assert r[0].children[1] == r[4]
    assert isinstance(r[6], Connection)
    assert r[6].source == r[4]
    assert r[6].target == r[2]
    assert isinstance(r[3], Software)
