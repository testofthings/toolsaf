"""Serializing IoT system and related class"""

from typing import Dict, Any, cast
import ipaddress

from toolsaf.common.address import Addresses, EntityTag, Network
from toolsaf.common.basics import HostType, Status, ExternalActivity
from toolsaf.common.entity import Entity
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.core.model import Addressable, Connection, Host, IoTSystem, NetworkNode, NodeComponent, Service
from toolsaf.core.components import Software, SoftwareComponent
from toolsaf.core.online_resources import OnlineResource
from toolsaf.common.serializer.serializer import Serializer, SerializerBase, SerializerStream


class IoTSystemSerializer(Serializer[IoTSystem]):
    """Serializer for IoT system"""
    def __init__(self, system: IoTSystem, unexpected: bool = True) -> None:
        super().__init__(IoTSystem)
        self.unexpected = unexpected
        self.verdict_cache: Dict[Entity, Verdict] = {}
        self.config.map_class("system", self)
        self.config.map_class("online-resource", OnlineResourceSerializer())
        self.config.map_class("network-node", NetworkNodeSerializer(self))
        self.config.map_class("network", NetworkSerializer())
        self.config.map_class("addressable", AddressableSerializer())
        self.config.map_class("host", HostSerializer())
        self.config.map_class("service", ServiceSerializer())
        self.config.map_class("connection", ConnectionSerializer())
        self.config.map_class("component", NodeComponentSerializer())
        self.config.map_class("sw", SoftwareSerializer())
        self.system = system

    def write(self, obj: IoTSystem, stream: SerializerStream) -> None:
        # Following parameters are not serialized:
        # concept_name, originals, message_listeners, model_listeners
        stream += "tag", "_"  # NOTE: A 'tag' for UI
        stream += "upload_tag", obj.upload_tag if obj.upload_tag else "_"

        for c in obj.get_connections():
            stream.push_object(c, at_object=obj)

        for online_resource in obj.online_resources:
            stream.push_object(online_resource, at_object=obj)

    def read(self, obj: IoTSystem, stream: SerializerStream) -> None:
        obj.upload_tag = stream - "upload_tag"


class OnlineResourceSerializer(Serializer[OnlineResource]):
    """Serializer for online resources"""
    def __init__(self) -> None:
        super().__init__(OnlineResource)
        self.config.map_simple_fields("name", "url", "keywords")

    def new(self, stream: SerializerStream) -> OnlineResource:
        return OnlineResource(stream["name"], stream["url"], stream["keywords"])

    def read(self, obj: OnlineResource, stream: SerializerStream) -> None:
        parent = stream.resolve("at", of_type=IoTSystem)
        parent.online_resources.append(obj)


class NetworkNodeSerializer(Serializer[NetworkNode]):
    """Base class for serializing network nodes"""
    def __init__(self, root: 'IoTSystemSerializer') -> None:
        super().__init__(NetworkNode)
        self.root = root
        self.config.abstract = True  # abstract class
        self.config.map_simple_fields("name")
        self.config.map_simple_fields("description")
        self.config.map_simple_fields("match_priority")

    def write(self, obj: NetworkNode, stream: SerializerStream) -> None:
        # Following parameters are not serialized:
        # concept_name
        stream += "address", obj.get_system_address().get_parseable_value()
        stream += "long_name", obj.long_name()
        stream += "host_type", obj.host_type.value
        stream += "status", obj.status.value

        expected = obj.get_expected_verdict(None)
        if expected:
            #Is this ever used? Is the actual expected just status from earlier?
            stream += "expected", expected.value  # fail or pass
        verdict = obj.get_verdict(self.root.verdict_cache)
        if verdict != Verdict.INCON:
            stream += "verdict", verdict.value
        if obj.external_activity:
            stream += "external_activity", obj.external_activity.value
        for c in obj.children:
            if not self.root.unexpected and not c.is_expected():
                continue
            stream.push_object(c, at_object=obj)
        for co in obj.components:
            stream.push_object(co, at_object=obj)

        for network in obj.networks:
            stream.push_object(network, at_object=obj)

        stream += "properties", {
            k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()
        }

    def read(self, obj: NetworkNode, stream: SerializerStream) -> None:
        obj.name = stream ["name"]
        obj.description = stream["description"]
        obj.match_priority = int(stream["match_priority"])
        # long_name is not an actual property, but a function
        obj.host_type = HostType(stream["host_type"])
        obj.status = Status(stream["status"])

        if "external_activity" in stream:
            obj.external_activity = ExternalActivity(int(stream ["external_activity"]))

        # Properties
        for key, value in cast(Dict[str, Dict[str, Any]], stream["properties"]).items():
            property_key = PropertyKey.parse(key)
            explanation = value.get("exp", "")
            if "verdict" in value:
                verdict = Verdict.parse(value["verdict"])
                obj.properties[property_key] = PropertyVerdictValue(verdict, explanation)
            else:
                sub_keys = {PropertyKey.parse(k) for k in value["set"]}
                obj.properties[property_key] = PropertySetValue(sub_keys, explanation)


class NetworkSerializer(Serializer[Network]):
    """Serializer for Network"""
    def __init__(self) -> None:
        super().__init__(Network)
        self.config.map_simple_fields("name")

    def write(self, obj: Network, stream: SerializerStream) -> None:
        if obj.ip_network:
            stream += "address", obj.ip_network.exploded

    def new(self, stream: SerializerStream) -> Network:
        if "address" not in stream:
            ip_network = ipaddress.ip_network(stream["address"])
        else:
            ip_network = None
        return Network(stream["name"], ip_network)

    def read(self, obj: Network, stream: SerializerStream) -> None:
        parent = stream.resolve("at", of_type=NetworkNode)
        if obj not in parent.networks:
            parent.networks.append(obj)


class AddressableSerializer(Serializer[Addressable]):
    """Base class for serializing addressable entities"""
    def __init__(self) -> None:
        super().__init__(Addressable)
        self.config.abstract = True  # abstract class

    def write(self, obj: Addressable, stream: SerializerStream) -> None:
        tag = obj.get_tag()
        if tag:
            # (unexpected entities do not have tags)
            stream += "tag", tag.get_parseable_value()
        if obj.addresses:
            stream += "addresses", [a.get_parseable_value() for a in obj.addresses if not a.is_tag()]
        if obj.any_host:
            stream += "any_host", True  # only write when True

    def read(self, obj: Addressable, stream: SerializerStream) -> None:
        obj.parent = stream.resolve("at", of_type=NetworkNode)
        obj.parent.children.append(obj)
        tag = stream - "tag"
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
        if obj.source not in stream or obj.target not in stream:
            # if endpoints not serialized, cannnot serialize connection
            return
        stream += "address", obj.get_system_address().get_parseable_value()
        stream += "source", stream.id_for(obj.source)
        stream += "target", stream.id_for(obj.target)
        stream += "source_long_name", obj.source.long_name()
        stream += "target_long_name", obj.target.long_name()

        s_tag, d_tag = obj.source.get_tag(), obj.target.get_tag()
        if s_tag and d_tag:
            # front-end can use this to identify connection
            stream += "tag", f"{s_tag}--{d_tag}"
        stream += "name", obj.target.name
        stream += "long_name", obj.long_name()

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
        # Following parameters are not serialized:
        # sub_components, status, tag
        stream += "status", obj.status.value
        stream += "address", obj.get_system_address().get_parseable_value()
        stream += "long_name", obj.long_name()

    def read(self, obj: NodeComponent, stream: SerializerStream) -> None:
        obj.status = Status(stream["status"])


class SoftwareSerializer(SerializerBase):
    """Serializer for Software"""
    def __init__(self) -> None:
        super().__init__(class_type=Software)

    def write(self, obj: Software, stream: SerializerStream) -> None:
        components = []
        for name, component in obj.components.items():
            components.append({
                "name": name,
                "version": component.version
            })
        stream += "components", components

    def new(self, stream: SerializerStream) -> Software:
        parent = stream.resolve("at", of_type=NetworkNode)
        software = Software(parent, stream["name"])
        parent.add_component(software)
        return software

    def read(self, obj: Software, stream: SerializerStream) -> None:
        for component in stream["components"]:
            name = component["name"]
            version = component["version"]
            obj.components[name] = SoftwareComponent(name, version)
