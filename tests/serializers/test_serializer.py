from typing import Any, List
from toolsaf.common.serializer.serializer import Serializer, SerializerBase, SerializerStream


def test_a_class():
    obj = AClass(a_string="AAA", a_int=2000)
    # 'obj' of class AClass is the object to write into 'json'
    ser = AClassSerializer()
    stream = SerializerStream(ser)
    js = list(stream.write(obj))
    assert js == [
        {"id": "id1", "a_string": "AAA", "a_int": 2000}
    ]
    ser = AClassSerializer()
    stream = SerializerStream(ser)
    read = list(stream.read(js))
    assert len(read) == 1


def test_b_class():
    obj = BClass()
    obj.sub_instances = [
        AClass("First", a_int = 101),
        AClass("Second", a_int = 102),
        AClass("Third", a_int = 103),
    ]
    ser = BClassSerializer()
    stream = SerializerStream(ser)
    js = list(stream.write(obj))
    assert js == [
        {"id": "id1"},
        {"id": "id2", "type": "a-type", "at": "id1", "a_string": "First", "a_int": 101},
        {"id": "id3", "type": "a-type", "at": "id1", "a_string": "Second", "a_int": 102},
        {"id": "id4", "type": "a-type", "at": "id1", "a_string": "Third", "a_int": 103},
    ]
    ser = BClassSerializer()
    stream = SerializerStream(ser)
    read = list(stream.read(js))
    read_b = read[0]
    assert isinstance(read_b, BClass)
    assert read_b.sub_instances == read[1:]
    assert read[1].a_string == "First"
    assert read[1].a_int == 101
    assert read[2].a_string == "Second"
    assert read[2].a_int == 102
    assert read[3].a_string == "Third"
    assert read[3].a_int == 103


class AClass:
    """Test class A for serialization"""
    def __init__(self, a_string: str = "", a_int: int = 0) -> None:
        self.a_string = a_string
        self.a_int = a_int

class AClassSerializer(Serializer[AClass]):
    """Serializer for A class"""
    def __init__(self):
        super().__init__(AClass)
        self.config.map_simple_fields("a_string", "a_int")

    def read(self, obj: AClass, stream: SerializerStream) -> None:
        parent = stream.resolve_optional(of_type=BClass)
        if parent:
            parent.sub_instances.append(obj)

class BClass:
    """Test class B for serializer"""
    def __init__(self):
        self.sub_instances: List[AClass] = []

class BClassSerializer(Serializer[BClass]):
    """Serializer for B class"""
    def __init__(self):
        super().__init__(BClass)
        self.config.map_class("a-type", AClassSerializer())

    def write(self, obj: BClass, stream: SerializerStream) -> None:
        stream.push_all(obj.sub_instances, at_object=obj)
