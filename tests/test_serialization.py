from tdsaf.core.model import IoTSystem
from tdsaf.serializer.serializer import SystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    su.system.system.name = "Test"
    serializer = SystemSerializer()
    writer = serializer.iot_system(su.get_system())
    js = list(writer.write_json())
    assert js

    reader = serializer.iot_system(IoTSystem())
    r = []
    for j in js:
        obj = reader.read_json_next(j)
        r.append(obj)
    assert r
