# pylint: disable=missing-class-docstring
"""Serializing IoT system and related class"""

from typing import Dict, Iterable, Optional, Type

from tdsaf.visualizer import Visualizer

from tdsaf.core.components import Software
from tdsaf.serializer.serializer import Serializer, SerializerContext, SerializerStream

from tdsaf.core.model import Addressable, Connection, Host, IoTSystem, NetworkNode, Service


class NetworkNodeSerializer(Serializer):
    def __init__(self, class_type: Type, root: 'IoTSystemSerializer'):
        super().__init__(class_type)
        self.root = root
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream):
        if not self.root.miniature:
            stream.write_field("long_name", obj.long_name())
        for c in obj.children:
            stream.push_object(c, at_object=obj)


class IoTSystemSerializer(NetworkNodeSerializer):
    def __init__(self, system: IoTSystem, visualizer: Optional[Visualizer] = None, miniature=False):
        super().__init__(IoTSystem, self)
        self.miniature = miniature
        self.config.type_name = "system"
        self.config.map_new_class("host", HostSerializer(self))
        self.config.map_new_class("service", ServiceSerializer(self))
        self.config.map_new_class("connection", ConnectionSerializer(self))
        self.config.map_new_class("sw", SoftwareSerializer(self))
        self.system = system
        self.visualizer = visualizer

    def write_json(self, context: Optional[SerializerContext]) -> Iterable[Dict]:
        """Write system to JSON"""
        stream = SerializerStream(context=context)
        return stream.write(self.system, self)


    def write(self, obj: IoTSystem, stream: SerializerStream):
        super().write(obj, stream)
        for c in obj.get_connections():
            stream.push_object(c, at_object=obj)

class AddressableSerializer(NetworkNodeSerializer):
    def write(self, obj: Addressable, stream: SerializerStream):
        super().write(obj, stream)
        if not self.root.miniature:
            stream.write_field("tag", obj.get_tag())

    def read(self, obj: Addressable, stream: SerializerStream):
        obj.parent = stream.resolve("at")
        obj.parent.children.append(obj)


class HostSerializer(AddressableSerializer):
    def __init__(self, root: IoTSystemSerializer):
        super().__init__(Host, root)

    def new(self, stream: SerializerStream) -> Host:
        return Host(stream.resolve("at"), stream["name"])

    def write(self, obj: Host, stream: SerializerStream):
        super().write(obj, stream)
        vis = self.root.visualizer
        if vis:
            stream.write_field("xy", vis.place(obj))
            image = vis.images.get(obj.name)
            if image:
                stream.write_field("image", image)



class ServiceSerializer(AddressableSerializer):
    def __init__(self, root: IoTSystemSerializer):
        super().__init__(Service, root)
        self.config.map_simple_fields("name")

    def new(self, stream: SerializerStream) -> Service:
        return Service(stream["name"], stream.resolve("at"))


class ConnectionSerializer(Serializer):
    def __init__(self, root: IoTSystemSerializer):
        super().__init__(Connection)
        self.root = root

    def new(self, stream: SerializerStream) -> Connection:
        return Connection(stream.resolve("source"), stream.resolve("target"))

    def write(self, obj: Connection, stream: SerializerStream):
        stream.write_field("source", stream.id_for(obj.source))
        stream.write_field("target", stream.id_for(obj.target))
        if not self.root.miniature:
            stream.write_field("name", obj.target.name)
            stream.write_field("long_name", obj.long_name())


class NodeComponentSerializer(Serializer):
    def __init__(self, class_type: Type, root: IoTSystemSerializer):
        super().__init__(class_type)
        self.root = root
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream):
        if not self.root.miniature:
            stream.write_field("long_name", obj.long_name())


class SoftwareSerializer(NodeComponentSerializer):
    def __init__(self, root: IoTSystemSerializer):
        super().__init__(Software, root)

    def new(self, stream: SerializerStream) -> Software:
        return Software(stream.resolve("at"), stream["name"])
