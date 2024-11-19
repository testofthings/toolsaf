from tdsaf.core.model import Connection, IoTSystem
from tdsaf.serializer.serializer import SerializerStream
from tdsaf.serializer.system_serializer import IoTSystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    su.system.system.name = "Test"
    ser = IoTSystemSerializer(su.system.system, miniature=True)
    stream = SerializerStream(ser)
    js = list(stream.write(ser.system))
    assert len(js) == 5
    assert js[0] == {"id": "id1", "type": "system", "name": "Test"}
    assert js[1] == {"id": "id2", "at": "id1", "type": "host", "name": "Device 1"}
    assert js[4] == {"id": "id5", "at": "id1", "type": "connection", "source": "id4", "target": "id3"}

    ser = IoTSystemSerializer(IoTSystem(), miniature=True)
    stream = SerializerStream(ser)
    r = list(stream.read(ser.system, js))
    assert len(r) == 5
    assert isinstance(r[0], IoTSystem)
    assert r[0].name == "Test"
    assert len(r[0].children) == 2
    assert r[0].children[0].name == "Device 1"
    assert r[0].children[0] == r[1]
    assert len(r[0].children[0].children) == 1
    assert r[0].children[0].children[0].name == "SSH:22"
    assert r[0].children[1] == r[3]
    assert isinstance(r[4], Connection)
    assert r[4].source == r[3]
    assert r[4].target == r[2]
