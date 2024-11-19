# pylint disable=missing-docstring
"""Serializing IoT system and related class"""

from typing import Type

from tdsaf.core.components import Software
from tdsaf.serializer.serializer import Serializer, SerializerStream

from tdsaf.core.model import Addressable, Connection, Host, IoTSystem, NetworkNode, Service


class NetworkNodeSerializer(Serializer):
    def __init__(self, class_type: Type, miniature=False):
        super().__init__(class_type)
        self.miniature = miniature
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream):
        if not self.miniature:
            stream.write_field("long_name", obj.long_name())
        for c in obj.children:
            stream.push_object(c, at_object=obj)


class AddressableSerializer(NetworkNodeSerializer):
    def write(self, obj: Addressable, stream: SerializerStream):
        super().write(obj, stream)
        if not self.miniature:
            stream.write_field("tag", obj.get_tag())

    def read(self, obj: Addressable, stream: SerializerStream):
        obj.parent = stream.resolve("at")
        obj.parent.children.append(obj)


class HostSerializer(AddressableSerializer):
    def __init__(self, miniature=False):
        super().__init__(Host, miniature)

    def new(self, stream: SerializerStream) -> Host:
        return Host(stream.resolve("at"), stream["name"])


class ServiceSerializer(AddressableSerializer):
    def __init__(self, miniature=False):
        super().__init__(Service, miniature)
        self.config.map_simple_fields("name")

    def new(self, stream: SerializerStream) -> Service:
        return Service(stream["name"], stream.resolve("at"))


class ConnectionSerializer(Serializer):
    def __init__(self, miniature=False):
        super().__init__(Connection)
        self.miniature = miniature

    def new(self, stream: SerializerStream) -> Connection:
        return Connection(stream.resolve("source"), stream.resolve("target"))

    def write(self, obj: Connection, stream: SerializerStream):
        stream.write_field("source", stream.id_for(obj.source))
        stream.write_field("target", stream.id_for(obj.target))
        if not self.miniature:
            stream.write_field("name", obj.target.name)
            stream.write_field("long_name", obj.long_name())


class NodeComponentSerializer(Serializer):
    def __init__(self, class_type: Type, miniature=False):
        super().__init__(class_type)
        self.miniature = miniature
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream):
        if not self.miniature:
            stream.write_field("long_name", obj.long_name())


class SoftwareSerializer(NodeComponentSerializer):
    def __init__(self, miniature=False):
        super().__init__(Software, miniature)

    def new(self, stream: SerializerStream) -> Software:
        return Software(stream.resolve("at"), stream["name"])


class IoTSystemSerializer(NetworkNodeSerializer):
    def __init__(self, system: IoTSystem, miniature=False):
        super().__init__(IoTSystem, miniature)
        self.config.type_name = "system"
        self.config.map_new_class("host", HostSerializer(miniature))
        self.config.map_new_class("service", ServiceSerializer(miniature))
        self.config.map_new_class("connection", ConnectionSerializer(miniature))
        self.config.map_new_class("sw", SoftwareSerializer(miniature))
        self.system = system

    def write(self, obj: IoTSystem, stream: SerializerStream):
        super().write(obj, stream)
        for c in obj.get_connections():
            stream.push_object(c, at_object=obj)
