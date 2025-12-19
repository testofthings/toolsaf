"""Serializing IoT system and related class"""

from typing import Dict, List, Any, cast
import ipaddress

from toolsaf.common.address import Addresses, EntityTag, Network, Protocol, DNSName
from toolsaf.common.basics import HostType, Status, ExternalActivity
from toolsaf.common.entity import Entity
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.core.model import Addressable, Connection, Host, IoTSystem, NetworkNode, NodeComponent, Service
from toolsaf.core.components import Software, SoftwareComponent, Cookies, CookieData
from toolsaf.core.online_resources import OnlineResource
from toolsaf.core.ignore_rules import IgnoreRules, IgnoreRule
from toolsaf.common.serializer.serializer import Serializer, SerializerBase, SerializerStream
from toolsaf.core.services import DHCPService, DNSService


class IoTSystemSerializer(Serializer[IoTSystem]):
    """Serializer for IoT system"""
    def __init__(self, system: IoTSystem, unexpected: bool = True) -> None:
        super().__init__(IoTSystem)
        self.unexpected = unexpected
        self.verdict_cache: Dict[Entity, Verdict] = {}
        self.config.map_class("system", self)
        self.config.map_class("ignore-rules", IgnoreRulesSerializer())
        self.config.map_class("online-resource", OnlineResourceSerializer())
        self.config.map_class("network-node", NetworkNodeSerializer(self))
        self.config.map_class("network", NetworkSerializer())
        self.config.map_class("addressable", AddressableSerializer())
        self.config.map_class("host", HostSerializer())
        self.config.map_class("dhcp-service", DHCPServiceSerializer())
        self.config.map_class("dns-service", DNSServiceSerializer())
        self.config.map_class("service", ServiceSerializer())
        self.config.map_class("connection", ConnectionSerializer())
        self.config.map_class("component", NodeComponentSerializer())
        self.config.map_class("cookies", CookiesSerializer())
        self.config.map_class("sw", SoftwareSerializer())
        self.system = system

    def write(self, obj: IoTSystem, stream: SerializerStream) -> None:
        # Following parameters are not serialized:
        # concept_name, originals, message_listeners, model_listeners
        stream += "upload_tag", obj.upload_tag if obj.upload_tag else "_"

        for c in obj.get_connections():
            stream.push_object(c, at_object=obj)

        for online_resource in obj.online_resources:
            stream.push_object(online_resource, at_object=obj)

        stream.push_object(obj.ignore_rules, at_object=obj)

    def read(self, obj: IoTSystem, stream: SerializerStream) -> None:
        obj.upload_tag = stream - "upload_tag"


class IgnoreRulesSerializer(Serializer[IgnoreRules]):
    """Serializer for ignore rules"""
    def __init__(self) -> None:
        super().__init__(IgnoreRules)

    def write(self, obj: IgnoreRules, stream: SerializerStream) -> None:
        rules: Dict[str, List[Dict[str, Any]]] = {}
        for file_type in obj.rules:
            rules[file_type] = []
            for rule in obj.rules[file_type]:
                rules[file_type].append(
                    {
                        "properties": [p.get_name() for p in rule.properties],
                        "at": list(rule.at),
                        "explanation": rule.explanation
                    }
                )
        stream += "rules", rules

    def new(self, stream: SerializerStream) -> IgnoreRules:
        parent = stream.resolve("at", of_type=IoTSystem)
        ignore_rules = IgnoreRules()
        parent.ignore_rules = ignore_rules
        return ignore_rules

    def read(self, obj: IgnoreRules, stream: SerializerStream) -> None:
        for file_type, rules in stream["rules"].items():
            obj.rules[file_type] = []
            for rule in rules:
                obj.rules[file_type] += [IgnoreRule(
                    file_type=file_type,
                    properties={PropertyKey.parse(p) for p in rule["properties"]},
                    at=set(rule["at"]),
                    explanation=rule["explanation"]
                )]


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

        if (external_activity := stream - "external_activity"):
            obj.external_activity = ExternalActivity(external_activity)

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

        if not isinstance(obj, IoTSystem):
            obj.get_system().originals.add(obj)


class NetworkSerializer(Serializer[Network]):
    """Serializer for Network"""
    def __init__(self) -> None:
        super().__init__(Network)
        self.config.map_simple_fields("name")

    def write(self, obj: Network, stream: SerializerStream) -> None:
        if obj.ip_network:
            stream += "address", obj.ip_network.exploded

    def new(self, stream: SerializerStream) -> Network:
        if (address := stream - "address"):
            ip_network = ipaddress.ip_network(address)
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
        addresses = []
        tag = obj.get_tag()

        if tag and not isinstance(obj, Service):
            # (unexpected entities do not have tags)
            addresses.append(tag.get_parseable_value())
        if obj.addresses:
            addresses += [a.get_parseable_value() for a in obj.addresses if not a.is_tag()]
        stream += "addresses", addresses
        if obj.any_host:
            stream += "any_host", True  # only write when True

    def read(self, obj: Addressable, stream: SerializerStream) -> None:
        obj.parent = stream.resolve("at", of_type=NetworkNode)
        obj.parent.children.append(obj)
        tag = stream - "tag"
        if tag and not isinstance(obj, Service):
            obj.addresses.add(EntityTag.new(tag))
        ads = stream.get("addresses") or []
        for a in ads:
            obj.addresses.add(Addresses.parse_endpoint(a))
        any_host = stream - "any_host"
        if any_host:
            obj.any_host = any_host


class HostSerializer(Serializer[Host]):
    """Serializer for Host"""
    def __init__(self) -> None:
        super().__init__(Host)

    def write(self, obj: Host, stream: SerializerStream) -> None:
        # Following parameters are not serialized:
        # concept_name
        if obj.ignore_name_requests:
            stream += "ignore_name_requests", [
                name.name
            for name in obj.ignore_name_requests]

    def new(self, stream: SerializerStream) -> Host:
        return Host(stream.resolve("at", of_type=IoTSystem), stream["name"])

    def read(self, obj: Host, stream: SerializerStream) -> None:
        ignore_name_reqs = stream - "ignore_name_requests"
        if ignore_name_reqs:
            for name in stream["ignore_name_requests"]:
                obj.ignore_name_requests.add(DNSName(name))


class ServiceSerializer(Serializer[Service]):
    """Serializer for Service"""
    def __init__(self) -> None:
        super().__init__(Service)
        self.config.map_simple_fields("name", "authentication", "client_side", "reply_from_other_address")

    def write(self, obj: Service, stream: SerializerStream) -> None:
        # Following parameters are not serialized:
        # concept_name
        if obj.protocol:
            stream += "protocol", obj.protocol.value
        stream += "con_type", obj.con_type.value
        if obj.multicast_target:
            stream += "multicast_source", obj.multicast_target.get_parseable_value()

    def new(self, stream: SerializerStream) -> Service:
        return Service(stream["name"], stream.resolve("at", of_type=Host))

    def read(self, obj: Service, stream: SerializerStream) -> None:
        obj.con_type = stream["con_type"]
        if (protocol := stream - "protocol"):
            obj.protocol = Protocol(protocol)
        if (multicast_source := stream - "multicast_source"):
            obj.multicast_target = Addresses.parse_address(multicast_source)


class DHCPServiceSerializer(Serializer[DHCPService]):
    """Serializer for DHCP service"""
    def __init__(self) -> None:
        super().__init__(DHCPService)

    def new(self, stream: SerializerStream) -> DHCPService:
        return DHCPService(stream.resolve("at", of_type=Host), stream["name"])


class DNSServiceSerializer(Serializer[DNSService]):
    """Serializer for DNS service"""
    def __init__(self) -> None:
        super().__init__(DNSService)

    def new(self, stream: SerializerStream) -> DNSService:
        return DNSService(stream.resolve("at", of_type=Host), stream["name"])


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
        stream += "status", obj.status.value

        s_tag, d_tag = obj.source.get_tag(), obj.target.get_tag()
        if s_tag and d_tag:
            # front-end can use this to identify connection
            stream += "tag", f"{s_tag}--{d_tag}"
        stream += "name", obj.target.name
        stream += "long_name", obj.long_name()

    def new(self, stream: SerializerStream) -> Connection:
        connection = Connection(
            stream.resolve("source", of_type=Addressable),
            stream.resolve("target", of_type=Addressable)
        )
        connection.source.get_parent_host().connections.append(connection)
        connection.target.get_parent_host().connections.append(connection)
        return connection

    def read(self, obj: Connection, stream: SerializerStream) -> None:
        obj.status = Status(stream["status"])
        obj.source.get_system().originals.add(obj)


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


class CookiesSerializer(Serializer[Cookies]):
    """Serializer for Cookies"""
    def __init__(self) -> None:
        super().__init__(Cookies)

    def write(self, obj: Cookies, stream: SerializerStream) -> None:
        cookies = {}
        for name, cookie in obj.cookies.items():
            cookies[name] = {
                "domain": cookie.domain,
                "path": cookie.path,
                "explanation": cookie.explanation
            }
        stream += "cookies", cookies

    def new(self, stream: SerializerStream) -> Cookies:
        parent = stream.resolve("at", of_type=NetworkNode)
        cookies = Cookies(parent, stream["name"])
        parent.add_component(cookies)
        return cookies

    def read(self, obj: Cookies, stream: SerializerStream) -> None:
        for name, cookie in stream["cookies"].items():
            obj.cookies[name] = CookieData(
                domain=cookie["domain"],
                path=cookie["path"],
                explanation=cookie["explanation"]
            )


class SoftwareSerializer(SerializerBase):
    """Serializer for Software"""
    def __init__(self) -> None:
        super().__init__(class_type=Software)

    def write(self, obj: Software, stream: SerializerStream) -> None:
        components = []
        for name, component in obj.components.items():
            components.append({
                "key": name,
                "component-name": component.name,
                "version": component.version
            })
        stream += "components", components
        if obj.permissions:
            stream += "permissions", list(obj.permissions)

    def new(self, stream: SerializerStream) -> Software:
        parent = stream.resolve("at", of_type=NetworkNode)
        software = Software(parent, stream["name"])
        parent.add_component(software)
        return software

    def read(self, obj: Software, stream: SerializerStream) -> None:
        for component in stream["components"]:
            key = component["key"]
            name = component["component-name"]
            version = component["version"]
            obj.components[key] = SoftwareComponent(name, version)
        if (permissions := stream - "permissions"):
            for permission in permissions:
                obj.permissions.add(permission)
                obj.properties[PropertyKey.create(("permission", permission))] = PropertyVerdictValue(Verdict.INCON)
