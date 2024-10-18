from tdsaf.core.model import IoTSystem
from tdsaf.serializer.serializer import SystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    su.system.system.name = "Test"
    writer = SystemSerializer(su.get_system())
    js = list(writer.write_json())
    assert js

    reader = SystemSerializer(su.get_system())
    r = []
    for j in js:
        obj = reader.read_json_next(j)
        r.append(obj)
    assert r
