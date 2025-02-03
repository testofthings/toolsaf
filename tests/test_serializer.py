from typing import Any, List
from toolsaf.common.serializer.serializer import Serializer, SerializerStream


def test_a_class():
    obj = AClass(a_string="AAA", a_int=2000)
    # 'obj' of class AClass is the object to write into 'json'
    ser = AClassSerializer()
    stream = SerializerStream(ser)
    r = list(stream.write(obj))
    assert r == [
        {"id": "id1", "a_string": "AAA", "a_int": 2000}
    ]

def test_b_class():
    obj = BClass()
    obj.sub_instances = [
        AClass("First", a_int = 101),
        AClass("Second", a_int = 102),
        AClass("Third", a_int = 103),
    ]
    ser = BClassSerializer()
    stream = SerializerStream(ser)
    r = list(stream.write(obj))
    assert r == [
        {"id": "id1"},
        {"id": "id2", "type": "a-type", "at": "id1", "a_string": "First", "a_int": 101},
        {"id": "id3", "type": "a-type", "at": "id1", "a_string": "Second", "a_int": 102},
        {"id": "id4", "type": "a-type", "at": "id1", "a_string": "Third", "a_int": 103},
    ]


class AClass:
    """Test class A for serialization"""
    def __init__(self, a_string: str, a_int: int) -> None:
        self.a_string = a_string
        self.a_int = a_int

class AClassSerializer(Serializer):
    """Serializer for A class"""
    def __init__(self):
        super().__init__(class_type=AClass)
        self.config.map_simple_fields("a_string", "a_int")

class BClass:
    """Test class B for serializer"""
    def __init__(self):
        self.sub_instances: List[AClass] = []

class BClassSerializer(Serializer):
    """Serializer for B class"""
    def __init__(self):
        super().__init__(class_type=BClass)
        self.config.map_new_class("a-type", AClassSerializer())

    def write(self, obj: Any, stream: SerializerStream) -> None:
        assert isinstance(obj, BClass)
        stream.push_all(obj.sub_instances, at_object=obj)

    def read(self, obj: Any, stream: SerializerStream) -> None:
        if isinstance(obj, AClass):
            parent = stream.resolve()
            assert isinstance(parent, BClass)
            parent.sub_instances.append(obj)
        else:
            raise ValueError("Unexpected", obj)
