"""Serializer"""

import json
from typing import Any, Callable, Dict, Generic, Iterable, List, Optional, Self, Type, TypeVar


T = TypeVar('T')


class SerializerContext:
    """Serializer context for body object"""
    def __init__(self, state: 'SerializerState', body: Any, mapper: Optional['ClassMapper'] = None):
        self.state = state
        self.body = body
        self.mapper = mapper or state.get_mapper(type(body))
        assert self.mapper, f"Class {type(body)} not mapped"
        self.parent: Optional[SerializerContext] = None
        self.sinks: Dict[Type, List[Any]] = {}
        self.state.contexts[body] = self
        if body not in self.state.reverse_ids:
            # allocate next identifier
            i = self.mapper.explicit_id(body) if self.mapper.explicit_id else None
            self.state.allocate(body, identifier=i)

    def list(self, attribute: List[Any], types: Iterable[Type]) -> Self:
        """Register list callback"""
        for t in types:
            self.sinks[t] = attribute
        for a in attribute:
            self.add(a)

    def add(self, body: Any, identifier: Optional[str] = None) -> 'SerializerContext':
        """Add object to serialize"""
        ctx = self.state.contexts.get(body)
        if ctx is not None:
            return ctx
        mapper = self.state.get_mapper(type(body))
        if identifier is not None:
            # allocate before registering
            self.state.allocate(body, identifier)
        if mapper.register_call:
            ctx = mapper.register_call(body)
        else:
            ctx = SerializerContext(self.state, body)
        ctx.parent = self
        return ctx

    def get_parent(self) -> Optional[Any]:
        """Get parent object, if any"""
        return self.parent.body if self.parent else None

    def write_json(self) -> Dict:
        """Convert to JSON. Internal method"""
        body_dict = {
            "id": self.state.reverse_ids.get(self.body, "?"),
            "type": self.mapper.type_name,
        }
        if self.parent:
            body_dict["at"] = self.state.reverse_ids[self.parent.body]
        for k, f in self.mapper.simple_attributes.items():
            body_dict[k] = getattr(self.body, f)
        for k in self.mapper.references:
            a = getattr(self.body, k)
            if a is not None:
                ids = self.state[a]
                body_dict[k] = ids
        for k, func in self.mapper.custom_writers.items():
            v = func(self)
            if v is not None:
                body_dict[k] = v
        return body_dict

    def __repr__(self) -> str:
        d = self.write_json()
        return json.dumps(d)


class SerializerState:
    """Serializer state"""
    def __init__(self):
        self.mappers: Dict[Type, ClassMapper] = {}
        self.mappers_by_names: Dict[str, ClassMapper] = {}
        self.contexts: Dict[Any, SerializerContext] = {}
        self.identifiers: Dict[str, Any] = {}
        self.reverse_ids: Dict[Any, str] = {}

    def get_mapper(self, for_type: Type) -> 'ClassMapper':
        """Get mapper for a type"""
        for cl in for_type.__mro__:
            mapper = self.mappers.get(cl)
            if mapper:
                return mapper
        assert False, f"Class {for_type.__name__} not mapped"

    def map_class(self, mapped_class: Type, type_name="") -> 'ClassMapper':
        """Create new class mapper"""
        m = ClassMapper(self, mapped_class, type_name)
        self.mappers[mapped_class] = m
        if type_name:
            self.mappers_by_names[type_name] = m
        return m

    def __getitem__(self, body: Any) -> str:
        """Get identifier for object"""
        i = self.reverse_ids.get(body)
        if i is None:
            mapper = self.get_mapper(type(body))
            assert mapper, f"Class {type(body)} not mapped"
            i = mapper.explicit_id(body) if mapper.explicit_id else None
            return self.allocate(body, identifier=i)
        return i

    def allocate(self, body: Any, identifier: Optional[str] = None) -> str:
        """Allocate identifier for object"""
        i = f"id{len(self.contexts)}" if identifier is None else identifier
        self.identifiers[i] = body
        self.reverse_ids[body] = i
        return i


class ConstructionData:
    """Construction-time data"""
    def __init__(self, context: SerializerContext, fields: Dict[str, Any], parent: Optional[Any] = None):
        self.context = context
        self.fields = fields
        self.parent = parent

    def __getitem__(self, key: str) -> Optional[Any]:
        """Get JSON field value"""
        return self.fields.get(key)

    def get_referenced(self, key: str) -> Optional[Any]:
        """Get object referenced by field specified by key"""
        ref = self.fields.get(key)
        if ref is None:
            return None
        return self.context.state.identifiers.get(ref)

    def __repr__(self) -> str:
        return f"{json.dumps(self.fields)}"


C = TypeVar('C')


class ClassMapper(Generic[C]):
    """Serializer data mapper"""
    def __init__(self, state: SerializerState, mapped_class: Type, type_name="") -> None:
        self.abstract = False
        self.state = state
        self.mapped_class = mapped_class
        self.type_name = type_name
        self.explicit_id: Optional[Callable[[Any], str]] = None  # explicit id resolver
        self.new_call: Optional[Callable[[SerializerContext], C]] = None
        self.register_call: Optional[Callable[[C], SerializerContext]] = None
        self.simple_attributes: Dict[str, str] = {}
        self.references: List[str] = []
        self.default_sub_type: Optional[Type] = None
        self.custom_writers: Dict[str, Callable[[SerializerContext], Any]] = {}
        self.custom_readers: Dict[str, Callable[[SerializerContext, Any], None]] = {}

    def derive(self, *mapped_class: Type) -> Self:
        """Derive mappings from other class(es)"""
        for m_class in mapped_class:
            m = self.state.mappers.get(m_class)
            assert m is not None, f"Class {m_class} not found"
            self.simple_attributes.update(m.simple_attributes)
            self.references.extend(m.references)
            self.custom_writers.update(m.custom_writers)
            if not self.register_call:
                # new call not derived
                self.register_call = m.register_call
        return self

    def default(self, *attribute: str) -> Self:
        """Default handling for attribute(s)"""
        for a in attribute:
            self.simple_attributes[a] = a
        return self

    def reference(self, *attribute: str) -> Self:
        """Handle attribute as reference"""
        self.references.extend(attribute)
        return self

    def new(self, call: Callable[[ConstructionData], C]) -> Self:
        """New object constructor"""
        self.new_call = call
        return self

    def register(self, call: Callable[[C], SerializerContext]) -> Self:
        """Register data sinks"""
        self.register_call = call
        return self

    def writer(self, attribute: str, function: Callable[[SerializerContext], Any]) -> Self:
        """Add custom attribute writer"""
        self.custom_writers[attribute] = function
        return self

    def reader(self, attribute: str, function: Callable[[SerializerContext, Any], None]) -> Self:
        """Add custom attribute reader"""
        self.custom_readers[attribute] = function
        return self

    def __enter__(self) -> 'ClassMapper':
        return self

    def __exit__(self, _type: Optional[Type[BaseException]], _val: Optional[BaseException], _tb):
        pass

    def __repr__(self) -> str:
        cl = self.mapped_class.__name__
        return f'"{self.type_name}" == {cl}' if self.type_name else cl


class AbstractSerializer:
    """Abstract serializer"""
    def __init__(self):
        self.serializer_state = SerializerState()

    def map_class(self, mapped_class: Type, type_name="") -> ClassMapper:
        """Create mapping for a class"""
        return self.serializer_state.map_class(mapped_class, type_name)

    def write_json(self) -> Iterable[Dict]:
        """Write to JSON"""
        for ctx in self.serializer_state.contexts.values():
            if not ctx.mapper.abstract:
                yield ctx.write_json()

    def iterate_writable(self) -> Iterable[SerializerContext]:
        """Iterate over all writable data"""
        for ctx in self.serializer_state.contexts.values():
            if not ctx.mapper.abstract:
                yield ctx

    def read_json(self, data: Dict) -> Any:
        """Read next object from JSON stream"""
        read_id = data["id"]
        parent_id = data.get("at")
        parent = self.serializer_state.identifiers.get(parent_id) if parent_id else None
        context = self.serializer_state.contexts.get(parent) if parent else None
        class_str = data.get("type")
        if not class_str:
            if not context or not context.mapper.default_sub_type:
                assert False, "No type specified and no default sub-type"
            mapper = context.mapper.default_sub_type
        else:
            mapper = self.serializer_state.mappers_by_names.get(class_str)
        assert mapper, f"Class {class_str} not mapped"
        if mapper.new_call:
            con_data = ConstructionData(context, data, parent)
            body = mapper.new_call(con_data)
        else:
            body = mapper.mapped_class()  # default constructor
        for k, f in mapper.simple_attributes.items():
            if k in data:
                setattr(body, f, data.get(k))
        if parent_id is None:
            # no parent
            self.serializer_state.allocate(body, identifier=read_id)
            if mapper.register_call:
                ctx = mapper.register_call(body)
            else:
                ctx = SerializerContext(self.serializer_state, body, mapper)
            self.call_custom_readers(mapper, ctx, data)
            return body
        assert context, f"Parent {parent_id} not found"
        ctx = context.add(body, identifier=read_id)
        self.call_custom_readers(mapper, ctx, data)
        sink = context.sinks.get(mapper.mapped_class)
        if sink is not None:
            sink.append(body)
        return body

    def call_custom_readers(self, mapper: ClassMapper, context: SerializerContext, data: Dict):
        """Call custom mappers"""
        for k, func in mapper.custom_readers.items():
            val = data.get(k)
            if val is not None:
                func(context, val)
