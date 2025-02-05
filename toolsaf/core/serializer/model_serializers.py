"""Serializing IoT system and related class"""

from typing import Dict

from toolsaf.common.address import Addresses, EntityTag
from toolsaf.common.basics import HostType
from toolsaf.common.entity import Entity
from toolsaf.common.verdict import Verdict
from toolsaf.core.model import Addressable, Connection, Host, IoTSystem, NetworkNode, NodeComponent, Service
from toolsaf.core.components import Software
from toolsaf.common.serializer.serializer import Serializer, SerializerBase, SerializerStream


class IoTSystemSerializer(Serializer[IoTSystem]):
    """Serializer for IoT system"""
    def __init__(self, system: IoTSystem, unexpected: bool = True) -> None:
        super().__init__(IoTSystem)
        self.unexpected = unexpected
        self.verdict_cache: Dict[Entity, Verdict] = {}
        self.config.type_name = "system"
        self.config.map_new_class("network-node", NetworkNodeSerializer(self))
        self.config.map_new_class("addressable", AddressableSerializer())
        self.config.map_new_class("host", HostSerializer())
        self.config.map_new_class("service", ServiceSerializer())
        self.config.map_new_class("connection", ConnectionSerializer())
        self.config.map_new_class("component", NodeComponentSerializer())
        self.config.map_new_class("sw", SoftwareSerializer())
        self.system = system

    def write(self, obj: IoTSystem, stream: SerializerStream) -> None:
        stream.write_field("tag", "_")  # NOTE: A 'tag' for UI
        for c in obj.get_connections():
            stream.push_object(c, at_object=obj)


class NetworkNodeSerializer(Serializer[NetworkNode]):
    """Base class for serializing network nodes"""
    def __init__(self, root: 'IoTSystemSerializer') -> None:
        super().__init__(NetworkNode)
        self.root = root
        self.config.abstract = True  # abstract class
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream) -> None:
        stream.write_field("address", obj.get_system_address().get_parseable_value())
        stream.write_field("long_name", obj.long_name())
        stream.write_field("host_type", obj.host_type.value)
        expected = obj.get_expected_verdict(None)
        if expected:
            stream.write_field("expected", expected.value)  # fail or pass
        verdict = obj.get_verdict(self.root.verdict_cache)
        if verdict != Verdict.INCON:
            stream.write_field("verdict", verdict.value)
        if obj.external_activity:
            stream.write_field("external_activity", obj.external_activity.value)
        for c in obj.children:
            if not self.root.unexpected and not c.is_expected():
                continue
            stream.push_object(c, at_object=obj)
        for co in obj.components:
            stream.push_object(co, at_object=obj)

    def read(self, obj: NetworkNode, stream: SerializerStream) -> None:
        obj.host_type = HostType(stream["host_type"])


class AddressableSerializer(Serializer[Addressable]):
    """Base class for serializing addressable entities"""
    def __init__(self) -> None:
        super().__init__(Addressable)
        self.config.abstract = True  # abstract class

    def write(self, obj: Addressable, stream: SerializerStream) -> None:
        tag = obj.get_tag()
        if tag:
            # (unexpected entities do not have tags)
            stream.write_field("tag", tag.get_parseable_value())
        if obj.addresses:
            stream.write_field("addresses", [a.get_parseable_value() for a in obj.addresses if not a.is_tag()])
        if obj.any_host:
            stream.write_field("any_host", True)  # only write when True

    def read(self, obj: Addressable, stream: SerializerStream) -> None:
        obj.parent = stream.resolve("at", of_type=Addressable)
        obj.parent.children.append(obj)
        tag = stream.get("tag")
        if tag:
            obj.addresses.add(EntityTag.new(tag))
        ads = stream.get("addresses") or []
        for a in ads:
            obj.addresses.add(Addresses.parse_address(a))


class HostSerializer(Serializer[Host]):
    """Serializer for Host"""
    def __init__(self) -> None:
        super().__init__(Host)

    def new(self, stream: SerializerStream) -> Host:
        return Host(stream.resolve("at", of_type=IoTSystem), stream["name"])


class ServiceSerializer(Serializer[Service]):
    """Serializer for Service"""
    def __init__(self) -> None:
        super().__init__(Service)
        self.config.map_simple_fields("name")

    def new(self, stream: SerializerStream) -> Service:
        return Service(stream["name"], stream.resolve("at", of_type=Host))


class ConnectionSerializer(Serializer[Connection]):
    """Serializer for Connection"""
    def __init__(self) -> None:
        super().__init__(Connection)

    def write(self, obj: Connection, stream: SerializerStream) -> None:
        stream.write_field("address", obj.get_system_address().get_parseable_value())
        stream.write_field("source", stream.id_for(obj.source))
        stream.write_field("target", stream.id_for(obj.target))
        stream.write_field("source_long_name", obj.source.long_name())
        stream.write_field("target_long_name", obj.target.long_name())

        s_tag, d_tag = obj.source.get_tag(), obj.target.get_tag()
        if s_tag and d_tag:
            # front-end can use this to identify connection
            stream.write_field("tag", f"{s_tag}--{d_tag}")
        stream.write_field("name", obj.target.name)
        stream.write_field("long_name", obj.long_name())

    def new(self, stream: SerializerStream) -> Connection:
        return Connection(stream.resolve("source", of_type=Addressable),
                          stream.resolve("target", of_type=Addressable))


class NodeComponentSerializer(Serializer[NodeComponent]):
    """Serializer for NodeComponent"""
    def __init__(self) -> None:
        super().__init__(NodeComponent)
        self.config.abstract = True  # abstract class
        self.config.map_simple_fields("name")

    def write(self, obj: NodeComponent, stream: SerializerStream) -> None:
        stream.write_field("address", obj.get_system_address().get_parseable_value())
        stream.write_field("long_name", obj.long_name())


class SoftwareSerializer(SerializerBase):
    """Serializer for Software"""
    def __init__(self) -> None:
        super().__init__(class_type=Software)

    def new(self, stream: SerializerStream) -> Software:
        return Software(stream.resolve("at", of_type=NetworkNode), stream["name"])
