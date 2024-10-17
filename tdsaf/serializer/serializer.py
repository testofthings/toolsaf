"""Serializer"""

import json
from typing import Any, Callable, Dict, Iterable, List, Optional, Self, Set, Type, TypeVar
from tdsaf.core.model import Host, IoTSystem, NetworkNode, Service

T = TypeVar('T')


class SerializerContext:
    """Serializer context"""
    def __init__(self, body: Any):
        self.body = body
        self.parent: Optional[SerializerContext] = None
        self.identifiers: Dict[str, SerializerContext] = {}
        self.reverse_ids: Dict[Any, str] = {}
        self.class_map = {}
        self.constructors: Dict[Type, Callable[[SerializerContext], SerializerContext]] = {}
        # per body
        self.simple_attributes: Dict[str, str] = {}
        self.sinks: Dict[Type, List[Any]] = {}

    def map(self, name: str, class_: Type,
            constructor: Optional[Callable[['SerializerContext'], Any]] = None,) -> 'SerializerContext':
        """Map class to string"""
        self.class_map[name] = class_
        if constructor:
            self.constructors[class_] = constructor
        return self

    def add(self, body: Any) -> 'SerializerContext':
        """Add object to serialize"""
        if self.body == body:
            # make sure mappings are ok
            i = str(len(self.identifiers))
            self.identifiers[i] = self
            self.reverse_ids[body] = i
            return self
        i = self.reverse_ids.get(body)
        if i:
            return self.identifiers[i]  # not added
        i = str(len(self.identifiers))
        ctx = SerializerContext(body)
        ctx.parent = self
        ctx.identifiers = self.identifiers
        ctx.reverse_ids = self.reverse_ids
        ctx.class_map = self.class_map
        self.identifiers[i] = ctx
        self.reverse_ids[body] = i
        return ctx

    def default(self, *attribute: str) -> Self:
        """Default handling for attribute(s)"""
        for a in attribute:
            self.simple_attributes[a] = a
        return self

    def list(self, attribute: List[T], types: Set[Type]) -> List[T]:
        """Handle list of objects"""
        for t in types:
            self.sinks[t] = attribute
        return attribute

    def __getitem__(self, key: str) -> Any:
        return getattr(self.body, key)

    def get_parent(self) -> Optional[Any]:
        """Get parent object, if any"""
        return self.parent.body if self.parent else None

    def write_json(self) -> Iterable[Dict]:
        """Write to JSON array"""
        class_reverse = {v: k for k, v in self.class_map.items()}

        for i, ctx in self.identifiers.items():
            yield ctx.as_json_(i, class_reverse)

    def read_json_next(self, data: Dict) -> Any:
        """Read next object from JSON stream"""
        read_id = data["id"]
        parent_id = data.get("at")
        class_str = data["type"]
        class_ = self.class_map.get(class_str)
        assert class_, f"Class {class_str} not in class map"
        if parent_id is not None:
            parent = self.identifiers.get(parent_id)
            assert parent, f"Parent {parent_id} not found"
        else:
            parent = self
        constructor = self.constructors.get(class_)
        if constructor:
            ctx = constructor(parent)
            body = ctx.body
        else:
            body = class_()  # default constructor
            ctx = self.add(body)
        for k, f in self.simple_attributes.items():
            if k in data:
                setattr(body, f, data.get(k))
        # new context
        self.identifiers[read_id] = ctx
        self.reverse_ids[body] = read_id
        sink = parent.sinks.get(class_)
        if sink is not None:
            sink.append(body)
        return body

    def as_json_(self, identifier: str, class_reverse: Dict[Type, str]) -> Dict:
        """Convert to JSON. Internal method"""
        class_str = class_reverse.get(type(self.body))
        assert class_str, f"Class {type(self.body)} not in class map"
        body_dict = {
            "id": identifier,
            "type": class_str,
        }
        if self.parent:
            body_dict["at"] = self.reverse_ids[self.parent.body]
        for k, f in self.simple_attributes.items():
            body_dict[k] = self[f]
        return body_dict

    def __repr__(self) -> str:
        class_reverse = {v: k for k, v in self.class_map.items()}
        d = self.as_json_(self.reverse_ids.get(self.body, "?"), class_reverse)
        return json.dumps(d)


class SystemSerializer():
    """IoT system serializer"""

    # pylint: disable=missing-function-docstring

    def node(self, body: NetworkNode, context: SerializerContext) -> SerializerContext:
        ctx = context.add(body)
        ctx.default("name")
        for c in ctx.list(body.children, {Host, Service}):
            self.node(c, ctx)
        return ctx

    def iot_system(self, body: IoTSystem) -> SerializerContext:
        ctx = SerializerContext(body)
        ctx.map("host", Host, lambda c: self.node(Host(body, c["name"]), c))
        ctx.map("service", Service, lambda c: self.node(Service(c["name"], c.get_parent()), c))
        ctx.map("system", IoTSystem)
        self.node(body, ctx)
        return ctx
