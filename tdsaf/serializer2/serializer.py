# pylint disable=missing-docstring
# pylint disable=missing-class-docstring

"""The new serializer module"""

from queue import Queue
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Type
from tdsaf.core.model import Addressable, Host, IoTSystem, NetworkNode, Service


class SerializerContext:
    """Serializer context"""
    def __init__(self):
        self.identifier_map: Dict[Any, str] = {}
        self.object_map: Dict[str, Any] = {}

    def resolve_id(self, obj: Any) -> str:
        """Resolve object id"""
        i = self.identifier_map.get(obj)
        if i is None:
            i = f"id{len(self.identifier_map) + 1}"
            self.identifier_map[obj] = i
            self.object_map[i] = obj
        return i

    def id_for(self, obj: Any) -> str:
        """Get existing object id"""
        i = self.identifier_map.get(obj)
        if i is None:
            raise ValueError(f"Object {obj} not found in context")
        return i


class SerializerStream:
    """JSON serialization stream"""
    def __init__(self, context: Optional[SerializerContext] = None) -> None:
        self.context = SerializerContext() if context is None else context
        self.queue: Queue[Tuple[Any, Any]] = Queue()
        self.data = {}

    def write(self, start: Any, serializer: 'Serializer') -> Iterable[Dict]:
        """Write to stream"""
        self.push_object(start)
        while not self.queue.empty():
            o, at = self.queue.get()
            self.data = {}
            self._write_object(o, at, serializer)
            yield self.data

    def read(self, start: Any, data: Iterable[Dict]) -> Iterable[Any]:
        """Read from stream"""
        serial = self.context.config.name_map.get(type(start))
        if not serial:
            raise ValueError(f"Serializer not found for {type(start)}")
        obj = start
        iterator = iter(data)
        self.data = next(iterator)
        self._read_object(serial, obj)

        # read the rest...
        self.data = next(iterator, default=None)
        while self.data is not None:
            type_name = self.data.get("type", "")
            serial = self.context.config.name_map.get(type_name)
            if not serial:
                raise ValueError(f"Serializer not found for {type_name}")
            obj = serial.new(self)
            if obj is None:
                raise ValueError(f"Serializer {serial} does not support new objects")
            post_process = self.context.config.post_process.get(serial)
            if post_process:
                post_process(obj)
            self._read_object(serial, obj)
            yield obj
            self.data = next(iterator, default=None)

    def push_object(self, obj: Any, at_object: Any = None):
        """Push object to queue"""
        self.queue.put((obj, at_object))

    def _write_object(self, obj: Any, at_object: Any, serializer: 'Serializer'):
        """Write object"""
        obj_type = type(obj)
        if obj_type == serializer.config.class_type:
            serial = serializer
        else:
            serial = serializer.config.class_map.get(obj_type)
        if not serial:
            raise ValueError(f"Serializer not found for {type(obj)}")
        ref = self.context.resolve_id(obj)
        self.data["id"] = ref
        if at_object:
            self.data["at"] = self.context.id_for(at_object)
        if serial.config.type_name:
            self.data["type"] = serial.config.type_name
        # write simple fields
        for field in serial.config.simple_fields:
            self.write_field(field, getattr(obj, field))
        # class specific write
        serial.write(obj, self)

    def write_field(self, field_name: str, value: Any):
        """Write custom field"""
        self.data[field_name] = value

    def _read_object(self, serializer: 'Serializer', obj: Any) -> Any:
        """Read object"""
        for field in serializer.config.simple_fields:
            setattr(obj, field, self.data[field])
        serializer.read(obj, self)
        id_s = self.data.get("id")
        if id_s:
            self.context.object_map[id_s] = obj
            self.context.identifier_map[obj] = id_s
        at_s = self.data.get("at")
        if at_s:
            at = self.context.object_map.get(at_s)
            if not at:
                raise ValueError(f"Object {at_s} not found")
            self.queue.put((obj, at))

    def __getitem__(self, field_name: str) -> Any:
        """Get attribute by key"""
        return self.data[field_name]

    def get(self, field_name: str) -> Optional[Any]:
        """Get attribute by key or null"""
        return self.data.get(field_name)

    def resolve(self, field_name: str) -> Any:
        """Resolve object pointed by field"""
        ref = self.data[field_name]
        return self.context.object_map.get(ref)


class SerializerConfiguration:
    """Serializer configuration"""
    def __init__(self, class_type: Type) -> None:
        self.class_type = class_type
        self.type_name = ""
        self.class_map: Dict[Type, Serializer] = {}
        self.name_map: Dict[str, Serializer] = {}
        self.post_process: Dict[Serializer, Callable[[Any], None]] = {}
        self.simple_fields: List[str] = []

    def map_simple_fields(self, *fields: str):
        """Map simple fields"""
        self.simple_fields.extend(fields)

    def map_new_class(self, type_name: str, serializer: 'Serializer',
                      post_process: Optional[Callable[[Any], None]] = None):
        """Map class"""
        self.name_map[type_name] = serializer
        serializer.config.type_name = type_name
        if serializer.config.class_type:
            self.class_map[serializer.config.class_type] = serializer
        if post_process:
            self.post_process[serializer] = post_process

    def new(self, _stream: SerializerStream) -> Any:
        """Create new object"""
        return self.class_type()


class Serializer:
    """Class serializer base class"""
    def __init__(self, class_type: Type) -> None:
        self.config = SerializerConfiguration(class_type)
        self.initialize()

    def initialize(self):
        """Initialize after construction"""

    def read(self, obj: Any, stream: SerializerStream):
        """Read new object"""

    def write(self, obj: NetworkNode, stream: SerializerStream):
        """Write object"""


class NetworkNodeSerializer(Serializer):
    def __init__(self, class_type: Type, miniature=False):
        super().__init__(class_type)
        self.miniature = miniature
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream):
        for c in obj.children:
            stream.push_object(c, at_object=obj)

    def read(self, obj: NetworkNode, stream: SerializerStream):
        obj.parent = stream.resolve("at")
        obj.parent.children.append(obj)


class AddressableSerializer(NetworkNodeSerializer):
    def write(self, obj: Addressable, stream: SerializerStream):
        super().write(obj, stream)
        if not self.miniature:
            stream.write_field("long_name", obj.long_name())
            stream.write_field("tag", obj.get_tag())


class HostSerializer(AddressableSerializer):
    def __init__(self, miniature=False):
        super().__init__(Host, miniature)

    def new(self, stream: SerializerStream) -> Host:
        return Host(stream.resolve("at"), stream["name"])


class ServiceSerializer(AddressableSerializer):
    def __init__(self, miniature=False):
        super().__init__(Service, miniature)

    def new(self, stream: SerializerStream) -> Service:
        return Service(stream["name"], stream.resolve("at"))


class IoTSystemSerializer(NetworkNodeSerializer):
    def __init__(self, system: IoTSystem, miniature=False):
        super().__init__(IoTSystem)
        self.config.type_name = "system"
        self.config.map_new_class("host", HostSerializer(miniature))
        self.config.map_new_class("service", ServiceSerializer(miniature))
        self.system = system
