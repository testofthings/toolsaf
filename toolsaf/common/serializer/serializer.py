"""Serializer module, to serialize and deserialize objects to JSON"""

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, Callable

class SerializerContext:
    """Serializer context"""
    def __init__(self) -> None:
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
    def __init__(self, serializer: 'Serializer', context: Optional[SerializerContext] = None) -> None:
        self.serializer = serializer
        self.context: SerializerContext = SerializerContext() if context is None else context
        self.push_to: List[Tuple[Any, Any]] = []
        self.data: Dict[str, Any] = {}

    def write(self, start: Any) -> Iterable[Dict[str, Any]]:
        """Write to stream"""
        self.push_object(start)
        queue = self.push_to
        while queue:
            o, at = queue[0]
            self.push_to = []
            self.data = {}
            send = self._write_object(o, at, self.serializer)
            if send:
                yield self.data
            queue = self.push_to + queue[1:] # depth first order

    def read(self, start: Any, data: Iterable[Dict[str, Any]]) -> Iterable[Any]:
        """Read from stream"""
        obj = start
        iterator = iter(data)
        next_data = next(iterator, None)
        if next_data is None:
            return
        self.data = next_data
        self._read_object(self.serializer, obj)
        yield obj

        # read the rest...
        next_data = next(iterator, None)
        while next_data is not None:
            self.data = next_data
            type_name = self.data.get("type", "")
            serial = self.serializer.config.name_map.get(type_name)
            if not serial:
                raise ValueError(f"Serializer not found for {type_name}")
            obj = serial.new(self)
            if obj is None:
                raise ValueError(f"Serializer {serial} does not support new objects")
            self._read_object(serial, obj)
            yield obj
            next_data = next(iterator, None)

    def push_object(self, obj: Any, at_object: Any = None) -> None:
        """Push object to queue"""
        self.push_to.append((obj, at_object))

    def push_all(self, iterator: Iterable[Any], at_object: Any = None) -> None:
        """Push all objects to queue"""
        for obj in iterator:
            self.push_to.append((obj, at_object))

    def _write_object(self, obj: Any, at_object: Any, serializer: 'Serializer') -> bool:
        """Write object"""
        obj_type = type(obj)
        if issubclass(obj_type, serializer.config.class_type):
            serial = serializer
        else:
            serial = serializer.config.find_serializer(obj_type)
        if serial.config.abstract:
            return False
        ref = serial.config.resolve_id(obj, self.context)
        self.data["id"] = ref
        if at_object:
            self.data["at"] = self.context.id_for(at_object)
        if serial.config.type_name:
            self.data["type"] = serial.config.type_name
        # write simple fields
        for field in serial.config.simple_fields:
            self.write_field(field, getattr(obj, field))
        # class specific write
        queue = self.push_to
        self.push_to = []
        serial.write(obj, self)
        for dec in serial.config.decorators:
            dec.write(obj, self)
        self.push_to = self.push_to + queue  # depth first order
        return True

    def write_field(self, field_name: str, value: Any) -> None:
        """Write custom field"""
        self.data[field_name] = value

    def _read_object(self, serializer: 'Serializer', obj: Any) -> None:
        """Read object"""
        for field in serializer.config.simple_fields:
            setattr(obj, field, self.data[field])
        serializer.read(obj, self)
        id_s = self.data.get("id")
        if id_s:
            self.context.object_map[id_s] = obj
            self.context.identifier_map[obj] = id_s
        for dec in serializer.config.decorators:
            dec.read(obj, self)

    def __getitem__(self, field_name: str) -> Any:
        """Get attribute by field name"""
        return self.data[field_name]

    def get(self, field_name: str) -> Optional[Any]:
        """Get attribute by field name or null"""
        return self.data.get(field_name)

    def resolve(self, field_name: str) -> Any:
        """Resolve object pointed by field"""
        ref = self.data[field_name]
        return self.context.object_map.get(ref)

    def write_object_id(self, field_name: str, obj: Any, optional: bool=False) -> None:
        """Write object id"""
        if obj is None or (optional and obj not in self.context.identifier_map):
            return  # nothing written
        ref = self.context.id_for(obj)
        self.data[field_name] = ref

    def __contains__(self, obj: Any) -> bool:
        """Is object in context"""
        return obj in self.context.identifier_map

    def id_for(self, obj: Any) -> str:
        """Get existing object id"""
        return self.context.id_for(obj)

    def __repr__(self) -> str:
        return json.dumps(self.data)  # best debugging help - JSON so far


class SerializerConfiguration:
    """Serializer configuration"""
    def __init__(self, class_type: Type[Any]) -> None:
        self.class_type = class_type
        self.abstract = False
        self.type_name = ""
        self.explicit_id: Optional[Callable[[Any], str]] = None
        self.simple_fields: List[str] = []
        self.decorators: List[Serializer] = []
        self.class_map: Dict[Type[Any], Serializer] = {}
        self.name_map: Dict[str, Serializer] = {}

    def map_simple_fields(self, *fields: str) -> None:
        """Map simple fields"""
        self.simple_fields.extend(fields)

    def map_new_class(self, type_name: str, serializer: 'Serializer') -> None:
        """Map class"""
        self.name_map[type_name] = serializer
        serializer.config.type_name = type_name
        if serializer.config.class_type:
            self.class_map[serializer.config.class_type] = serializer

    def add_decorator(self, decorator: 'Serializer', sub_type: Optional[Type[Any]] = None) -> None:
        """Add decorator"""
        if not sub_type:
            # add on this level
            self.decorators.append(decorator)
        else:
            # add by sub type
            if issubclass(self.class_type, sub_type):
                self.decorators.append(decorator)
            for s in self.class_map.values():
                s.config.add_decorator(decorator, sub_type=sub_type)

    def find_serializer(self, for_type: Type[Any]) -> 'Serializer':
        """Find serializer for type"""
        ser = self.class_map.get(for_type)
        if ser:
            return ser
        for sc in for_type.__mro__:
            ser = self.class_map.get(sc)
            if ser:
                return ser
        raise ValueError(f"Serializer not found for {for_type}")

    def resolve_id(self, obj: Any, context: SerializerContext) -> str:
        """Resolve object id"""
        if self.explicit_id is not None:
            ids = self.explicit_id(obj)
            context.identifier_map[obj] = ids
            context.object_map[ids] = obj
        else:
            ids = context.resolve_id(obj)
        return ids

    def __repr__(self) -> str:
        return self.class_type.__name__


class Serializer:
    """Class serializer base class"""
    def __init__(self, class_type: Type[Any]) -> None:
        self.config = SerializerConfiguration(class_type)
        self.initialize()

    def initialize(self) -> None:
        """Initialize after construction"""

    def write(self, obj: Any, stream: SerializerStream) -> None:
        """Custom write definitions"""

    def new(self, stream: SerializerStream) -> Any:
        """Create new object"""
        return self.config.class_type(stream)

    def read(self, obj: Any, stream: SerializerStream) -> None:
        """Custom read definitions"""

    def __repr__(self) -> str:
        return str(self.config)
