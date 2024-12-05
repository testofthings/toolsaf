# pylint: disable=missing-class-docstring
"""Serializing IoT system and related class"""

from typing import Optional, Type

from tdsaf.common.address import Addresses, EntityTag

from tdsaf.visualizer import Visualizer

from tdsaf.core.components import Software
from tdsaf.serializer.serializer import Serializer, SerializerStream

from tdsaf.core.model import Addressable, Connection, Host, IoTSystem, NetworkNode, NodeComponent, Service


class NetworkNodeSerializer(Serializer):
    def __init__(self, class_type: Type, root: 'IoTSystemSerializer'):
        super().__init__(class_type)
        self.root = root
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream):
        if not self.root.miniature:
            stream.write_field("long_name", obj.long_name())
        if self.root.verdicts:
            expected = obj.get_expected_verdict(None)
            if expected:
                stream.write_field("expected", expected.value)  # fail or pass
            stream.write_field("verdict", obj.get_verdict(self.root.verdict_cache).value)
        for c in obj.children:
            if not self.root.unexpected and not c.is_expected():
                continue
            stream.push_object(c, at_object=obj)
        for c in obj.components:
            stream.push_object(c, at_object=obj)


class IoTSystemSerializer(NetworkNodeSerializer):
    def __init__(self, system: IoTSystem, visualizer: Optional[Visualizer] = None, miniature=False, unexpected=True,
                 verdicts=False):
        super().__init__(IoTSystem, self)
        self.miniature = miniature
        self.unexpected = unexpected
        self.verdicts = verdicts
        self.verdict_cache = {}
        self.config.type_name = "system"
        self.config.map_new_class("host", HostSerializer(self))
        self.config.map_new_class("service", ServiceSerializer(self))
        self.config.map_new_class("connection", ConnectionSerializer(self))
        self.config.map_new_class("component", NodeComponentSerializer(self))
        self.config.map_new_class("sw", SoftwareSerializer(self))
        self.system = system
        self.visualizer = visualizer

    def write(self, obj: IoTSystem, stream: SerializerStream):
        super().write(obj, stream)
        for c in obj.get_connections():
            stream.push_object(c, at_object=obj)

class AddressableSerializer(NetworkNodeSerializer):
    def write(self, obj: Addressable, stream: SerializerStream):
        super().write(obj, stream)
        if not self.root.miniature and obj.get_tag():
            # (unexpected entities do not have tags)
            stream.write_field("tag", obj.get_tag().get_parseable_value())
        if not self.root.miniature and obj.addresses:
            stream.write_field("addresses", [a.get_parseable_value() for a in obj.addresses if not a.is_tag()])

    def read(self, obj: Addressable, stream: SerializerStream):
        obj.parent = stream.resolve("at")
        obj.parent.children.append(obj)
        tag = stream.get("tag")
        if tag:
            obj.addresses.add(EntityTag.new(tag))
        ads = stream.get("addresses") or []
        for a in ads:
            obj.addresses.add(Addresses.parse_address(a))


class HostSerializer(AddressableSerializer):
    def __init__(self, root: IoTSystemSerializer):
        super().__init__(Host, root)

    def new(self, stream: SerializerStream) -> Host:
        return Host(stream.resolve("at"), stream["name"])

    def write(self, obj: Host, stream: SerializerStream):
        super().write(obj, stream)
        vis = self.root.visualizer
        if vis and obj.visual:
            stream.write_field("xy", vis.place(obj))
            image_and_z = vis.images.get(obj)
            if image_and_z:
                stream.write_field("image", image_and_z)



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
    def __init__(self, root: IoTSystemSerializer, class_type=NodeComponent):
        super().__init__(class_type)
        self.root = root
        self.config.abstract = True  # do not create instances of this class
        self.config.map_simple_fields("name")

    def write(self, obj: NetworkNode, stream: SerializerStream):
        if not self.root.miniature:
            stream.write_field("long_name", obj.long_name())


class SoftwareSerializer(NodeComponentSerializer):
    def __init__(self, root: IoTSystemSerializer):
        super().__init__(root, class_type=Software)
        self.config.abstract = False

    def new(self, stream: SerializerStream) -> Software:
        return Software(stream.resolve("at"), stream["name"])
