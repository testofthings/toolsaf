from tdsaf.serializer.serializer import SystemSerializer
from tests.test_model_new import Setup_1


def test_simple_model():
    su = Setup_1()
    seralizer = SystemSerializer()
    ctx = seralizer.iot_system(su.get_system())
    js = list(ctx.write_json())
    assert js
