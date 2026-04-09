"""Model serializers"""
from typing import Dict, Any, Optional, List, Annotated, Union, Literal, TypedDict
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from toolsaf.common.basics import Status, ExternalActivity, HostType, ConnectionType
from toolsaf.common.verdict import Verdict
from toolsaf.common.address import Protocol, Addresses, DNSName
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.core.model import (
    NetworkNode, IoTSystem, Addressable, Host, Service,
    NodeComponent, Connection
)
from toolsaf.core.address_ranges import MulticastTarget, PortRange
from toolsaf.core.ignore_rules import IgnoreRules, IgnoreRule
from toolsaf.core.services import DHCPService, DNSService
from toolsaf.core.components import Software, SoftwareComponent


class NetworkNodeOutDTO(TypedDict):
    """Serializes network nodes to JSON"""
    name: str
    description: str
    match_priority: int
    system_address: str
    host_type: HostType
    status: Status
    expected: Optional[Verdict] = None
    verdict: Optional[Verdict] = None
    external_activity: ExternalActivity
    properties: Dict[str, Any] = {}


class IgnoreRuleOutDTO(TypedDict):
    """Serializes ignore rules to JSON"""
    properties: List[str]
    at: List[str]
    explanation: str


class IgnoreRulesOutDTO(TypedDict):
    """Serializes ignore rules to JSON"""
    rules: Dict[str, List[IgnoreRuleOutDTO]] # file type, related rules


class IoTSystemOutDTO(NetworkNodeOutDTO):
    """Serializes IoT systems to JSON"""
    type: Literal["system"] = "system"
    upload_tag: str
    ignore_rules: IgnoreRulesOutDTO


class AddressableOutDTO(NetworkNodeOutDTO):
    """Serializes addressable entities to JSON"""
    addresses: List[str]
    parent: str # Parent system address
    any_host: bool


class HostOutDTO(AddressableOutDTO):
    """Serializes hosts to JSON"""
    type: Literal["host"] = "host"
    ignore_name_requests: List[str]


class ServiceOutDTO(AddressableOutDTO):
    """Serializes services to JSON"""
    type: Literal["service"] = "service"
    protocol: Optional[Protocol]
    con_type: ConnectionType
    authentication: bool
    client_side: bool
    multicast_target: Optional[str]
    port_range: Optional[str]
    reply_from_other_address: bool


class DHCPServiceOutDTO(ServiceOutDTO):
    """Serializes DHCP services to JSON"""
    type: Literal["dhcp-service"] = "dhcp-service"


class DNSServiceOutDTO(ServiceOutDTO):
    """Serializes DNS services to JSON"""
    type: Literal["dns-service"] = "dns-service"


class NodeComponentOutDTO(TypedDict):
    """Serializes node components to JSON"""
    name: str
    system_address: str
    status: Status
    parent: str # Parent system address


class SoftwareOutDTO(NodeComponentOutDTO):
    """Serializes software components to JSON"""
    type: Literal["software"] = "software"
    components: List["SoftwareComponentOutDTO"]
    permissions: List[str]


class SoftwareComponentOutDTO(TypedDict):
    """Serializes software components to JSON"""
    key: str
    name: str
    version: str


class ConnectionOutDTO(TypedDict):
    """Serializes connections to JSON"""
    type: Literal["connection"] = "connection"
    system_address: str
    source_system_address: str
    target_system_address: str
    status: Status
    properties: Dict[str, Any]


iot_system_adapter = TypeAdapter(IoTSystemOutDTO)
host_adapter = TypeAdapter(HostOutDTO)
service_adapter = TypeAdapter(ServiceOutDTO)
dhcp_service_adapter = TypeAdapter(DHCPServiceOutDTO)
dns_service_adapter = TypeAdapter(DNSServiceOutDTO)
software_adapter = TypeAdapter(SoftwareOutDTO)
connection_adapter = TypeAdapter(ConnectionOutDTO)


UnionDTO = Annotated[
    Union[
        "IoTSystemOutDTO",
        "HostOutDTO",
        "ServiceOutDTO",
        "DHCPServiceOutDTO",
        "DNSServiceOutDTO",
        "SoftwareOutDTO",
        "ConnectionOutDTO"
    ],
    Field(discriminator="type")
]
NodeAdapter = TypeAdapter(UnionDTO)


class EpicSerializer:
    """Serializes the whole model to JSON"""
    def __init__(self):
        self.model_map: Dict[str, Addressable] = {} # sys_addr, model object
        self.verdict_map: Dict[str, Verdict] = {} # sys_addr, verdict
        self.serializer_map = {
            IoTSystem: self._serialize_iot_system,
            Host: self._serialize_host,
            Service: self._serialize_service,
            DHCPService: self._serialize_dhcp_service,
            DNSService: self._serialize_dns_service,
            Software: self._serialize_software,
            Connection: self._serialize_connection
        }


    def serialize(self, obj: Any) -> Dict[str, Any]:
        """Serialize an object to JSON"""
        if not (serializer := self.serializer_map.get(type(obj))):
            raise ValueError(f"Unsupported object type: {type(obj)}")
        serialized = {}
        serializer(obj, serialized)
        return serialized


    def deserialize(self, data: Dict[str, Any]) -> Any:
        """Deserialize an object from JSON"""
        NodeAdapter.validate_python(data)
        match data["type"]:
            case "system":
                model = IoTSystem()
                self._populate_iot_system(model, data)

            case "host":
                model = Host(parent=self.model_map[data["parent"]], name=data["name"])
                self._populate_host(model, data)

            case "dhcp-service":
                model = DHCPService(parent=self.model_map[data["parent"]], name=data["name"])
                self._populate_service(model, data)

            case "dns-service":
                model = DNSService(parent=self.model_map[data["parent"]], name=data["name"])
                self._populate_service(model, data)

            case "service":
                model = Service(name=data["name"], parent=self.model_map[data["parent"]])
                self._populate_service(model, data)

            case "software":
                model = Software(entity=self.model_map[data["parent"]], name=data["name"])
                self._populate_software(model, data)

            case "connection":
                model = Connection(
                    source=self.model_map[data["source_system_address"]],
                    target=self.model_map[data["target_system_address"]]
                )

            case _:
                raise ValueError(f"Unsupported type: {type(data['type'])}")

        return model

    def _serialize_network_node(self, obj: NetworkNode, data: Dict[str, Any]) -> None:
        """FIXME"""
        data.update({
            "name": obj.name,
            "description": obj.description,
            "match_priority": obj.match_priority,
            "system_address": obj.get_system_address().get_parseable_value(),
            "host_type": obj.host_type,
            "status": obj.status.value,
            "expected": obj.get_expected_verdict(None).value if obj.get_expected_verdict(None) else None,
            "verdict": obj.get_verdict(self.verdict_map).value if obj.get_verdict(self.verdict_map) else None,
            "external_activity": obj.external_activity.value,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        })

    def _populate_network_node(self, obj: NetworkNode, data: "NetworkNodeOutDTO") -> None:
        """Populate a network node with data from JSON"""
        # Not setting: system_address, expected, verdict
        obj.name = data["name"]
        obj.description = data["description"]
        obj.match_priority = data["match_priority"]
        obj.host_type = data["host_type"]
        obj.status = data["status"]
        obj.external_activity = data["external_activity"]

        for key, value in data["properties"].items():
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

        self.model_map[data["system_address"]] = obj

    def _serialize_addressable(self, obj: Addressable, data: Dict[str, Any]) -> None:
        """FIXME"""
        self._serialize_network_node(obj, data)
        addresses = [a.get_parseable_value() for a in obj.addresses if not a.is_tag()]
        if (tag := obj.get_tag()) and not isinstance(obj, Service):
            addresses.append(tag.get_parseable_value())
        data.update({
            "addresses": addresses,
            "parent": obj.parent.get_system_address().get_parseable_value(),
            "any_host": obj.any_host
        })

    def _populate_addressable(self, obj: Addressable, data: "AddressableOutDTO") -> None:
        """Populate an addressable entity with data from JSON"""
        self._populate_network_node(obj, data)
        for address in data["addresses"]:
            obj.addresses.add(Addresses.parse_endpoint(address))
        obj.parent = self.model_map[data["parent"]]
        obj.parent.children.append(obj)
        obj.any_host = data["any_host"]

    def _serialize_ignore_rules(self, obj: IgnoreRules, data: Dict[str, Any]) -> None:
        """FIXME"""
        rules: Dict[str, List[Dict[str, Any]]] = {}
        for file_type in obj.rules:
            rules[file_type] = []
            for rule in obj.rules[file_type]:
                rules[file_type].append({
                    "properties": [p.get_name() for p in rule.properties],
                    "at": list(rule.at),
                    "explanation": rule.explanation
                })
        data["ignore_rules"] = {"rules": rules}

    def _serialize_iot_system(self, obj: IoTSystem, data: Dict[str, Any]) -> None:
        """FIXME"""
        self._serialize_network_node(obj, data)
        self._serialize_ignore_rules(obj.ignore_rules, data)
        data.update({
            "type": "system",
            "upload_tag": obj.upload_tag
        })

    def _populate_iot_system(self, obj: IoTSystem, data: "IoTSystemOutDTO") -> None:
        """Populate an IoT system with data from JSON"""
        self._populate_network_node(obj, data)
        obj.upload_tag = data["upload_tag"]
        for file_type, rules in data["ignore_rules"]["rules"].items():
            obj.ignore_rules.rules[file_type] = [IgnoreRule(
                file_type=file_type,
                properties={PropertyKey.parse(p) for p in rule["properties"]},
                at=set(rule["at"]),
                explanation=rule["explanation"]
            ) for rule in rules]

    def _serialize_host(self, obj: Host, data: Dict[str, Any]) -> None:
        """FIXME"""
        self._serialize_addressable(obj, data)
        data.update({
            "type": "host",
            "ignore_name_requests": [dns_name.name for dns_name in obj.ignore_name_requests]
        })

    def _populate_host(self, obj: Host, data: "HostOutDTO") -> Host:
        """Populate a host with data from JSON"""
        self._populate_addressable(obj, data)
        for dns_name in data["ignore_name_requests"]:
            obj.ignore_name_requests.add(DNSName(dns_name))
        return obj

    def _serialize_service(self, obj: Service, data: Dict[str, Any]) -> None:
        """FIXME"""
        self._serialize_addressable(obj, data)
        data.update({
            "type": "service",
            "protocol": obj.protocol.value if obj.protocol else None,
            "con_type": obj.con_type.value,
            "authentication": obj.authentication,
            "client_side": obj.client_side,
            "multicast_target": obj.multicast_target.get_parseable_value() if obj.multicast_target else None,
            "port_range": obj.port_range.get_parseable_value() if obj.port_range else None,
            "reply_from_other_address": obj.reply_from_other_address
        })

    def _populate_service(self, obj: Service, data: "ServiceOutDTO") -> None:
        """Populate a service with data from JSON"""
        self._populate_addressable(obj, data)
        obj.protocol = data["protocol"]
        obj.con_type = data["con_type"]
        obj.authentication = data["authentication"]
        obj.client_side = data["client_side"]
        if data["multicast_target"]:
            obj.multicast_target = MulticastTarget.parse_address_range(data["multicast_target"])
        if data["port_range"]:
            obj.port_range = PortRange.parse_port_range(data["port_range"])
        obj.reply_from_other_address = data["reply_from_other_address"]

    def _serialize_dhcp_service(self, obj: DHCPService, data: Dict[str, Any]) -> None:
        """FIXME"""
        self._serialize_service(obj, data)
        data["type"] = "dhcp-service"

    def _serialize_dns_service(self, obj: DNSService, data: Dict[str, Any]) -> None:
        """FIXME"""
        self._serialize_service(obj, data)
        data["type"] = "dns-service"

    def _serialize_node_component(self, obj: NodeComponent, data: Dict[str, Any]) -> None:
        """FIXME"""
        data.update({
            "name": obj.name,
            "system_address": obj.get_system_address().get_parseable_value(),
            "status": obj.status.value,
            "parent": obj.entity.get_system_address().get_parseable_value()
        })

    def _serialize_software(self, obj: Software, data: Dict[str, Any]) -> None:
        """FIXME"""
        self._serialize_node_component(obj, data)
        data.update({
            "type": "software",
            "components": [{
                "key": key,
                "name": component.name,
                "version": component.version
            } for key, component in obj.components.items()],
            "permissions": list(obj.permissions)
        })

    def _populate_software(self, obj: Software, data: "SoftwareOutDTO") -> None:
        """Populate a software component with data from JSON"""
        for component_data in data["components"]:
            obj.components[component_data["key"]] = SoftwareComponent(
                name=component_data["name"],
                version=component_data["version"]
            )
        obj.permissions = set(data["permissions"])

    def _serialize_connection(self, obj: Connection, data: Dict[str, Any]) -> None:
        """FIXME"""
        data.update({
            "type": "connection",
            "system_address": obj.get_system_address().get_parseable_value(),
            "source_system_address": obj.source.get_system_address().get_parseable_value(),
            "target_system_address": obj.target.get_system_address().get_parseable_value(),
            "status": obj.status.value,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        })
