"""Serializer"""

import json
from typing import Any, Callable, Dict, Generic, Iterable, List, Optional, Self, Type, TypeVar
from tdsaf.core.model import Host, IoTSystem, NetworkNode, Service

T = TypeVar('T')


class SerializerContext:
    """Serializer context"""
    def __init__(self, controller: 'SerializationController', body: Any, mapper: Optional['ClassMapper'] = None):
        self.controller = controller
        self.body = body
        self.mapper = mapper or controller.mappers.get(type(body))
        assert self.mapper, f"Class {type(body)} not mapped"
        self.parent: Optional[SerializerContext] = None
        self.sinks: Dict[Type, List[Any]] = {}
        # map from controller
        self.controller.contexts[body] = self
        if body not in self.controller.reverse_ids:
            # allocate next identifier
            self.controller.allocate(body)

    def list(self, attribute: List[Any], types: Iterable[Type]) -> Self:
        """Register list callback"""
        for t in types:
            self.sinks[t] = attribute
        for a in attribute:
            self.add(a)

    def add(self, body: Any, identifier: Optional[str] = None) -> 'SerializerContext':
        """Add object to serialize"""
        ctx = self.controller.contexts.get(body)
        if ctx is not None:
            return ctx
        mapper = self.controller.mappers.get(type(body))
        assert mapper, f"Class {type(body)} not mapped"
        if identifier is not None:
            # allocate before registering
            self.controller.allocate(body, identifier)
        if mapper.register_call:
            ctx = mapper.register_call(body)
        else:
            ctx = SerializerContext(self.controller, body)
        ctx.parent = self
        return ctx

    def __getitem__(self, key: str) -> Any:
        return getattr(self.body, key)

    def get_parent(self) -> Optional[Any]:
        """Get parent object, if any"""
        return self.parent.body if self.parent else None

    def write_json(self) -> Dict:
        """Convert to JSON. Internal method"""
        body_dict = {
            "id": self.controller.reverse_ids.get(self.body, "?"),
            "type": self.mapper.type_name,
        }
        if self.parent:
            body_dict["at"] = self.controller.reverse_ids[self.parent.body]
        for k, f in self.mapper.simple_attributes.items():
            body_dict[k] = self[f]
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
            if not self.new_call:
                # new call not derived
                self.register_call = m.register_call
        return self

    def default(self, *attribute: str) -> Self:
        """Default handling for attribute(s)"""
        for a in attribute:
            self.simple_attributes[a] = a
        return self

    def new(self, call: Callable[[SerializerContext], C]) -> Self:
        """New object handling"""
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
    def __init__(self, root: Any):
        self.control = SerializationController()
        self.root = root

    def write_json(self) -> Iterable[Dict]:
        """Write to JSON"""
        for ctx in self.control.contexts.values():
            yield ctx.write_json()

    def read_json_next(self, data: Dict) -> Any:
        """Read next object from JSON stream"""
        read_id = data["id"]
        parent_id = data.get("at")
        class_str = data["type"]
        mapper = self.control.mappers_by_names.get(class_str)
        assert mapper, f"Class {class_str} not mapped"
        if parent_id is not None:
            parent = self.control.identifiers.get(parent_id)
        else:
            parent = self.root
        context = self.control.contexts.get(parent)
        assert context, f"Parent {parent_id} not found"
        if mapper.new_call:
            body = mapper.new_call(self)
        else:
            body = mapper.mapped_class()  # default constructor
        context.add(body, identifier=read_id)
        for k, f in mapper.simple_attributes.items():
            if k in data:
                setattr(body, f, data.get(k))
        sink = context.sinks.get(mapper.mapped_class)
        if sink is not None:
            sink.append(body)
        return body


class SystemSerializer(AbstractSerializer):
    """IoT system serializer"""
    def __init__(self, system: IoTSystem):
        super().__init__(system)

        with self.control(NetworkNode) as m:
            m.default("name")
            m.register(self.network_node)

        with self.control(Host, "host").derive(NetworkNode) as m:
            m.new(lambda c: Host(c.get_parent(), c["name"]))

        with self.control(Service, "service").derive(NetworkNode) as m:
            m.new(lambda c: Service(c["name"], c.get_parent()))

        self.control(IoTSystem, "system").derive(NetworkNode)

        # register callbacks
        self.iot_system(system)

    # pylint: disable=missing-function-docstring

    def network_node(self, new: NetworkNode) -> SerializerContext:
        ctx = SerializerContext(self.control, new)
        ctx.list(new.children, {Host, Service})
        return ctx

    def iot_system(self, new: IoTSystem) -> SerializerContext:
        return self.network_node(new)
