"""Serializer"""

import json
from typing import Any, Callable, Dict, Iterable, List, Optional, Self, Type, TypeVar
from tdsaf.core.model import Host, IoTSystem, NetworkNode, Service

T = TypeVar('T')


class SerializerContext:
    """Serializer context"""
    def __init__(self, body: Any, class_map: Dict[str, Type] = None):
        self.body = body
        self.parent: Optional[SerializerContext] = None
        self.identifiers: Dict[str, SerializerContext] = {}
        self.reverse_ids: Dict[Any, str] = {}
        self.class_map = {} if class_map is None else class_map
        # per body
        self.simple_attributes: Dict[str, str] = {}
        self.list_attributes: Dict[str, List[Any]] = {}

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
        ctx = SerializerContext(body, self.class_map)
        ctx.parent = self
        ctx.identifiers = self.identifiers
        ctx.reverse_ids = self.reverse_ids
        self.identifiers[i] = ctx
        self.reverse_ids[body] = i
        return ctx

    def default(self, *attribute: str) -> Self:
        """Default handling for attribute(s)"""
        for a in attribute:
            self.simple_attributes[a] = a
        return self

    def list(self, attribute: List[T], field:str) -> List[T]:
        """Handle list of objects"""
        self.list_attributes[field] = attribute
        return attribute

    def write_json(self) -> Iterable[Dict]:
        """Write to JSON array"""
        class_reverse = {v: k for k, v in self.class_map.items()}

        for i, ctx in self.identifiers.items():
            yield ctx.as_json_(i, class_reverse)

    def as_json_(self, identifier: str, class_reverse: Dict[Type, str]) -> Dict:
        """Convert to JSON. Internal method"""
        class_str = class_reverse.get(type(self.body))
        assert class_str, f"Class {type(self.body)} not in class map"
        body_dict = {
            "id": identifier,
            "type": class_str,
        }
        if self.parent:
            body_dict["parent"] = self.reverse_ids[self.parent.body]
        for k, f in self.simple_attributes.items():
            body_dict[k] = getattr(self.body, f)
        return body_dict

    def __repr__(self) -> str:
        class_reverse = {v: k for k, v in self.class_map.items()}
        d = self.as_json_(self.reverse_ids.get(self.body, "?"), class_reverse)        
        return json.dumps(d)


class SystemSerializer():
    """IoT system serializer"""

    # pylint: disable=missing-function-docstring

    def network_node(self, body: NetworkNode, context: SerializerContext):
        ctx = context.add(body)
        ctx.default("name")
        for c in ctx.list(body.children, "nodes"):
            self.network_node(c, ctx)

    def iot_system(self, body: IoTSystem) -> SerializerContext:
        context = SerializerContext(body, class_map={
            "system": IoTSystem,
            "host": Host,
            "service": Service,
        })
        self.network_node(body, context)
        return context
