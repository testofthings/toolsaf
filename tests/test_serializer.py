from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.components import Software
from toolsaf.core.model import Connection, IoTSystem
from toolsaf.core.serializer.model_serializers import IoTSystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    su.system.finish_()  # creates SW components
    su.system.system.name = "Test"
    ser = IoTSystemSerializer(su.system.system, miniature=True)
    stream = SerializerStream(ser)
    js = list(stream.write(ser.system))
    assert len(js) == 7
    assert js[0] == {"id": "id1", "type": "system", "name": "Test"}
    assert js[1] == {"id": "id2", "at": "id1", "type": "host", "name": "Device 1"}
    assert js[3] == {"id": "id4", "at": "id2", "type": "sw", "name": "Device 1 SW"}
    assert js[6] == {"id": "id7", "at": "id1", "type": "connection", "source": "id5", "target": "id3"}

    ser = IoTSystemSerializer(IoTSystem(), miniature=True)
    stream = SerializerStream(ser)
    r = list(stream.read(ser.system, js))
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