from tdsaf.core.model import Connection, IoTSystem
from tdsaf.serializer.serializer import SystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    su.system.system.name = "Test"
    writer = SystemSerializer(miniature=True)
    writer.iot_system(su.get_system())
    js = list(writer.write_json())
    assert len(js) == 5
    assert js[0] == {"id": "1", "type": "system", "name": "Test"}
    assert js[1] == {"id": "2", "at": "1", "type": "host", "name": "Device 1"}
    assert js[4] == {"id": "5", "at": "1", "type": "connection", "source": "4", "target": "3"}

    reader = SystemSerializer(miniature=True)
    r = []
    for j in js:
        obj = reader.read_json(j)
        r.append(obj)
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
