"""Model serializers"""
from typing import Callable, Dict, Any, Optional, List, Annotated, Union, Literal
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
NODE_ADAPTER: TypeAdapter[UnionDTO] = TypeAdapter(UnionDTO)


class EpicSerializer:
    """Serializes the whole model to JSON"""
    def __init__(self) -> None:
        self.model_map: Dict[str, Any] = {} # sys_addr, model object
        self.verdict_map: Dict[Any, Verdict] = {} # entity, verdict
        self.serializer_map: Dict[type, Callable[..., None]] = {
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
        serialized: Dict[str, Any] = {}
        serializer(obj, serialized)
        return serialized

    def deserialize(self, data: Dict[str, Any]) -> Any:
        """Deserialize an object from JSON"""
        dto = NODE_ADAPTER.validate_python(data)
        return dto.to_model(self.model_map)

    def _serialize_network_node(self, obj: NetworkNode, data: Dict[str, Any]) -> None:
        """Serialize network node"""
        expected = obj.get_expected_verdict(None)
        verdict = obj.get_verdict(self.verdict_map)
        data.update({
            "name": obj.name,
            "description": obj.description,
            "match_priority": obj.match_priority,
            "system_address": obj.get_system_address().get_parseable_value(),
            "host_type": obj.host_type,
            "status": obj.status.value,
            "expected": expected.value if expected else None,
            "verdict": verdict.value,
            "external_activity": obj.external_activity.value,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        })

    def _serialize_addressable(self, obj: Addressable, data: Dict[str, Any]) -> None:
        """Serialize addressable"""
        self._serialize_network_node(obj, data)
        addresses = [a.get_parseable_value() for a in obj.addresses if not a.is_tag()]
        if (tag := obj.get_tag()) and not isinstance(obj, Service):
            addresses.append(tag.get_parseable_value())
        data.update({
            "addresses": addresses,
            "parent": obj.parent.get_system_address().get_parseable_value(),
            "any_host": obj.any_host
        })

    def _serialize_ignore_rules(self, obj: IgnoreRules, data: Dict[str, Any]) -> None:
        """Serialize ignore rules"""
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
        """Serialize IoT system"""
        self._serialize_network_node(obj, data)
        self._serialize_ignore_rules(obj.ignore_rules, data)
        data.update({
            "type": "system",
            "upload_tag": obj.upload_tag
        })

    def _serialize_host(self, obj: Host, data: Dict[str, Any]) -> None:
        """Serialize host"""
        self._serialize_addressable(obj, data)
        data.update({
            "type": "host",
            "ignore_name_requests": [dns_name.name for dns_name in obj.ignore_name_requests]
        })

    def _serialize_service(self, obj: Service, data: Dict[str, Any]) -> None:
        """Serialize service"""
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

    def _serialize_dhcp_service(self, obj: DHCPService, data: Dict[str, Any]) -> None:
        """Serialize DHCP service"""
        self._serialize_service(obj, data)
        data["type"] = "dhcp-service"

    def _serialize_dns_service(self, obj: DNSService, data: Dict[str, Any]) -> None:
        """Serialize DNS service"""
        self._serialize_service(obj, data)
        data["type"] = "dns-service"

    def _serialize_node_component(self, obj: NodeComponent, data: Dict[str, Any]) -> None:
        """Serialize node component"""
        data.update({
            "name": obj.name,
            "system_address": obj.get_system_address().get_parseable_value(),
            "status": obj.status.value,
            "parent": obj.entity.get_system_address().get_parseable_value()
        })

    def _serialize_software(self, obj: Software, data: Dict[str, Any]) -> None:
        """Serialize software"""
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

    def _serialize_connection(self, obj: Connection, data: Dict[str, Any]) -> None:
        """Serialize connection"""
        data.update({
            "type": "connection",
            "system_address": obj.get_system_address().get_parseable_value(),
            "source_system_address": obj.source.get_system_address().get_parseable_value(),
            "target_system_address": obj.target.get_system_address().get_parseable_value(),
            "status": obj.status.value,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        })


class BaseDTO(BaseModel):
    """Base DTO class"""
    model_config = ConfigDict(from_attributes=True)


class NetworkNodeOutDTO(BaseDTO):
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

    def populate(self, model: NetworkNode, model_map: Dict[str, Any]) -> None:
        """Populate a network node model from this DTO"""
        model.name = self.name
        model.description = self.description
        model.match_priority = self.match_priority
        model.host_type = self.host_type
        model.status = self.status
        model.external_activity = self.external_activity
        for key, value in self.properties.items():
            property_key = PropertyKey.parse(key)
            explanation = value.get("exp", "")
            if "verdict" in value:
                verdict = Verdict.parse(value["verdict"])
                model.properties[property_key] = PropertyVerdictValue(verdict, explanation)
            else:
                sub_keys = {PropertyKey.parse(k) for k in value["set"]}
                model.properties[property_key] = PropertySetValue(sub_keys, explanation)
        if not isinstance(model, IoTSystem):
            model.get_system().originals.add(model)
        model_map[self.system_address] = model


class IgnoreRuleOutDTO(BaseDTO):
    """Serializes ignore rules to JSON"""
    properties: List[str]
    at: List[str]
    explanation: str


class IgnoreRulesOutDTO(BaseDTO):
    """Serializes ignore rules to JSON"""
    rules: Dict[str, List[IgnoreRuleOutDTO]] # file type, related rules


class IoTSystemOutDTO(NetworkNodeOutDTO):
    """Serializes IoT systems to JSON"""
    type: Literal["system"] = "system"
    upload_tag: str
    ignore_rules: IgnoreRulesOutDTO

    def to_model(self, model_map: Dict[str, Any]) -> IoTSystem:
        """Create and populate an IoTSystem from this DTO"""
        model = IoTSystem()
        super().populate(model, model_map)
        model.upload_tag = self.upload_tag
        for file_type, rules in self.ignore_rules.rules.items():
            model.ignore_rules.rules[file_type] = [IgnoreRule(
                file_type=file_type,
                properties={PropertyKey.parse(p) for p in rule.properties},
                at=set(rule.at),
                explanation=rule.explanation
            ) for rule in rules]
        return model


class AddressableOutDTO(NetworkNodeOutDTO):
    """Serializes addressable entities to JSON"""
    addresses: List[str]
    parent: str # Parent system address
    any_host: bool

    def populate(self, model: NetworkNode, model_map: Dict[str, Any]) -> None:
        """Populate an addressable model from this DTO"""
        super().populate(model, model_map)
        assert isinstance(model, Addressable)
        for address in self.addresses:
            model.addresses.add(Addresses.parse_endpoint(address))
        model.parent = model_map[self.parent]
        model.parent.children.append(model)
        model.any_host = self.any_host


class HostOutDTO(AddressableOutDTO):
    """Serializes hosts to JSON"""
    type: Literal["host"] = "host"
    ignore_name_requests: List[str]

    def to_model(self, model_map: Dict[str, Any]) -> Host:
        """Create and populate a Host from this DTO"""
        model = Host(parent=model_map[self.parent], name=self.name)
        super().populate(model, model_map)
        for dns_name in self.ignore_name_requests:
            model.ignore_name_requests.add(DNSName(dns_name))
        return model


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

    def populate(self, model: NetworkNode, model_map: Dict[str, Any]) -> None:
        """Populate a service model from this DTO"""
        super().populate(model, model_map)
        assert isinstance(model, Service)
        model.protocol = self.protocol
        model.con_type = self.con_type
        model.authentication = self.authentication
        model.client_side = self.client_side
        if self.multicast_target:
            model.multicast_target = MulticastTarget.parse_address_range(self.multicast_target)
        if self.port_range:
            model.port_range = PortRange.parse_port_range(self.port_range)
        model.reply_from_other_address = self.reply_from_other_address

    def to_model(self, model_map: Dict[str, Any]) -> Service:
        """Create and populate a Service from this DTO"""
        model = Service(name=self.name, parent=model_map[self.parent])
        self.populate(model, model_map)
        return model


class DHCPServiceOutDTO(ServiceOutDTO):
    """Serializes DHCP services to JSON"""
    type: Literal["dhcp-service"] = "dhcp-service"  # type: ignore[assignment]

    def to_model(self, model_map: Dict[str, Any]) -> DHCPService:
        """Create and populate a DHCPService from this DTO"""
        model = DHCPService(parent=model_map[self.parent], name=self.name)
        super().populate(model, model_map)
        return model


class DNSServiceOutDTO(ServiceOutDTO):
    """Serializes DNS services to JSON"""
    type: Literal["dns-service"] = "dns-service"  # type: ignore[assignment]

    def to_model(self, model_map: Dict[str, Any]) -> DNSService:
        """Create and populate a DNSService from this DTO"""
        model = DNSService(parent=model_map[self.parent], name=self.name)
        super().populate(model, model_map)
        return model


class NodeComponentOutDTO(BaseDTO):
    """Serializes node components to JSON"""
    name: str
    system_address: str
    status: Status
    parent: str # Parent system address

    def populate(self, model: NodeComponent, model_map: Dict[str, Any]) -> None:
        """Populate a node component model from this DTO"""
        model_map[self.system_address] = model
        model.status = self.status


class SoftwareOutDTO(NodeComponentOutDTO):
    """Serializes software components to JSON"""
    type: Literal["software"] = "software"
    components: List["SoftwareComponentOutDTO"]
    permissions: List[str]

    def to_model(self, model_map: Dict[str, Any]) -> Software:
        """Create and populate a Software from this DTO"""
        model = Software(entity=model_map[self.parent], name=self.name)
        super().populate(model, model_map)
        for component_dto in self.components:
            model.components[component_dto.key] = SoftwareComponent(
                name=component_dto.name,
                version=component_dto.version
            )
        model.permissions = set(self.permissions)
        return model


class SoftwareComponentOutDTO(BaseDTO):
    """Serializes software components to JSON"""
    key: str
    name: str
    version: str


class ConnectionOutDTO(BaseDTO):
    """Serializes connections to JSON"""
    type: Literal["connection"] = "connection"
    system_address: str
    source_system_address: str
    target_system_address: str
    status: Status
    properties: Dict[str, Any]

    def to_model(self, model_map: Dict[str, Any]) -> Connection:
        """Create a Connection from this DTO"""
        return Connection(
            source=model_map[self.source_system_address],
            target=model_map[self.target_system_address]
        )
