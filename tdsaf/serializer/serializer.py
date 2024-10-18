"""Serializer"""

import json
from typing import Any, Callable, Dict, Generic, Iterable, List, Optional, Self, Type, TypeVar
from tdsaf.core.model import Host, IoTSystem, NetworkNode, Service

T = TypeVar('T')


class SerializerContext:
    """Serializer context"""
    def __init__(self, control: 'SerializationController', body: Any, mapper: Optional['ClassMapper'] = None):
        self.control = control
        self.body = body
        self.mapper = mapper or control.mappers.get(type(body))
        assert self.mapper, f"Class {type(body)} not mapped"
        self.parent: Optional[SerializerContext] = None
        self.sinks: Dict[Type, List[Any]] = {}
        # map from controller
        self.control.contexts[body] = self
        if body not in self.control.reverse_ids:
            # allocate next identifier
            self.control.allocate(body)

    def list(self, attribute: List[Any], types: Iterable[Type]) -> Self:
        """Register list callback"""
        for t in types:
            self.sinks[t] = attribute
        for a in attribute:
            self.add(a)

    def add(self, body: Any, identifier: Optional[str] = None) -> 'SerializerContext':
        """Add object to serialize"""
        ctx = self.control.contexts.get(body)
        if ctx is not None:
            return ctx
        mapper = self.control.mappers.get(type(body))
        assert mapper, f"Class {type(body)} not mapped"
        if identifier is not None:
            # allocate before registering
            self.control.allocate(body, identifier)
        if mapper.register_call:
            ctx = mapper.register_call(body)
        else:
            ctx = SerializerContext(self.control, body)
        ctx.parent = self
        return ctx

    def get_parent(self) -> Optional[Any]:
        """Get parent object, if any"""
        return self.parent.body if self.parent else None

    def write_json(self) -> Dict:
        """Convert to JSON. Internal method"""
        body_dict = {
            "id": self.control.reverse_ids.get(self.body, "?"),
            "type": self.mapper.type_name,
        }
        if self.parent:
            body_dict["at"] = self.control.reverse_ids[self.parent.body]
        for k, f in self.mapper.simple_attributes.items():
            body_dict[k] = getattr(self.body, f)
        return body_dict

    def __repr__(self) -> str:
        d = self.write_json()
        return json.dumps(d)


class SerializationController:
    """Serialization controller"""
    def __init__(self):
        self.mappers: Dict[Type, ClassMapper] = {}
        self.mappers_by_names: Dict[str, ClassMapper] = {}
        self.contexts: Dict[Any, SerializerContext] = {}
        self.identifiers: Dict[str, Any] = {}
        self.reverse_ids: Dict[Any, str] = {}

    def __call__(self, mapped_class: Type, type_name="") -> 'ClassMapper':
        """Map local data"""
        m = ClassMapper(self, mapped_class, type_name)
        self.mappers[mapped_class] = m
        if type_name:
            self.mappers_by_names[type_name] = m
        return m

    def allocate(self, body: Any, identifier: Optional[str] = None) -> str:
        """Allocate identifier for object"""
        i = str(len(self.contexts)) if identifier is None else identifier
        self.identifiers[i] = body
        self.reverse_ids[body] = i
        return i


class ConstructionData:
    """Construction-time data"""
    def __init__(self, fields: Dict[str, Any], parent: Optional[Any] = None):
        self.fields = fields
        self.parent = parent

    def __getitem__(self, key: str) -> Optional[Any]:
        return self.fields.get(key)

    def __repr__(self) -> str:
        return f"{json.dumps(self.fields)}"


C = TypeVar('C')


class ClassMapper(Generic[C]):
    """Local data mapper"""
    def __init__(self, controller: SerializationController, mapped_class: Type, type_name="") -> None:
        self.controller = controller
        self.mapped_class = mapped_class
        self.type_name = type_name
        self.new_call: Optional[Callable[[SerializerContext], C]] = None
        self.register_call: Optional[Callable[[C], SerializerContext]] = None
        self.simple_attributes: Dict[str, str] = {}

    def derive(self, *mapped_class: Type) -> Self:
        """Derive mappings from other class(es)"""
        for m_class in mapped_class:
            m = self.controller.mappers.get(m_class)
            assert m is not None, f"Class {m_class} not found"
            self.simple_attributes.update(m.simple_attributes)
            if not self.register_call:
                # new call not derived
                self.register_call = m.register_call
        return self

    def default(self, *attribute: str) -> Self:
        """Default handling for attribute(s)"""
        for a in attribute:
            self.simple_attributes[a] = a
        return self

    def new(self, call: Callable[[ConstructionData], C]) -> Self:
        """New object constructor"""
        self.new_call = call
        return self

    def register(self, call: Callable[[C], SerializerContext]) -> Self:
        """Register data sinks"""
        self.register_call = call
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
        self.control = SerializationController()

    def write_json(self) -> Iterable[Dict]:
        """Write to JSON"""
        for ctx in self.control.contexts.values():
            yield ctx.write_json()

    def read_json(self, data: Dict) -> Any:
        """Read next object from JSON stream"""
        read_id = data["id"]
        parent_id = data.get("at")
        class_str = data["type"]
        parent = self.control.identifiers.get(parent_id) if parent_id else None
        mapper = self.control.mappers_by_names.get(class_str)
        assert mapper, f"Class {class_str} not mapped"
        if mapper.new_call:
            con_data = ConstructionData(data, parent)
            body = mapper.new_call(con_data)
        else:
            body = mapper.mapped_class()  # default constructor
        for k, f in mapper.simple_attributes.items():
            if k in data:
                setattr(body, f, data.get(k))

        if parent_id is None:
            # no parent
            self.control.allocate(body, identifier=read_id)
            if mapper.register_call:
                mapper.register_call(body)
            else:
                SerializerContext(self.control, body, mapper)
            return body

        context = self.control.contexts.get(parent)
        assert context, f"Parent {parent_id} not found"
        context.add(body, identifier=read_id)
        sink = context.sinks.get(mapper.mapped_class)
        if sink is not None:
            sink.append(body)
        return body


class SystemSerializer(AbstractSerializer):
    """IoT system serializer"""
    def __init__(self):
        super().__init__()

        with self.control(NetworkNode) as m:
            m.default("name")
            m.register(self.network_node)

        with self.control(Host, "host").derive(NetworkNode) as m:
            m.new(lambda c: Host(c.parent, c["name"]))

        with self.control(Service, "service").derive(NetworkNode) as m:
            m.new(lambda c: Service(c["name"], c.parent))

        self.control(IoTSystem, "system").derive(NetworkNode)

    # pylint: disable=missing-function-docstring

    def network_node(self, new: NetworkNode) -> SerializerContext:
        ctx = SerializerContext(self.control, new)
        ctx.list(new.children, {Host, Service})
        return ctx

    def iot_system(self, new: IoTSystem) -> SerializerContext:
        return self.network_node(new)
