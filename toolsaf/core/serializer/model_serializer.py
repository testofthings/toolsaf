"""Model (de)serialization"""
from typing import (
    Callable, Dict, Any, Optional, List, Annotated, Union, Literal, Set
)
import logging
import ipaddress
from pydantic import (
    BaseModel, ConfigDict, Field, TypeAdapter, field_validator,
    IPvAnyNetwork
)

from toolsaf.common.entity import Entity
from toolsaf.common.traffic import Flow
from toolsaf.common.basics import Status, ExternalActivity, HostType, ConnectionType
from toolsaf.common.verdict import Verdict
from toolsaf.common.address import Protocol, DNSName, Network, AnyAddress
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.android import MobilePermissions
from toolsaf.core.model import (
    NetworkNode, IoTSystem, Addressable, Host, Service,
    NodeComponent, Connection
)
from toolsaf.core.address_ranges import MulticastTarget, PortRange
from toolsaf.core.ignore_rules import IgnoreRules, IgnoreRule
from toolsaf.core.services import DHCPService, DNSService
from toolsaf.core.components import Software, SoftwareComponent, Cookies, CookieData
from toolsaf.core.serializer.types import (
    LongNameType, NameType, DescriptionType, MatchPriorityType, SystemAddressType, UploadTagType,
    validate_property_keys
)

LOGGER = logging.getLogger(__name__)


class SystemSerializer:
    """Serialize and deserialize IoT systems and their contents"""
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
            Cookies: self._serialize_cookies,
            Connection: self._serialize_connection,
            Network: self._serialize_network,
        }
        self._queue: List[Any] = []

    def serialize(self, obj: Any) -> List[Dict[str, Any]]:
        """Serialize an object and its children to JSON"""
        result, stack = [], [obj]
        while stack:
            self._queue = []
            obj = stack.pop()
            if not (serializer := self.serializer_map.get(type(obj))):
                LOGGER.debug("No serializer found for object of type %s", type(obj))
                continue
            serialized: Dict[str, Any] = {}
            serializer(obj, serialized)
            result.append(serialized)
            if self._queue:
                stack.extend(reversed(self._queue)) # Depth first
        return result

    def serialize_set(self, obj_set: Set[Any]) -> List[Dict[str, Any]]:
        """Serialize a given set of objects"""
        result = []
        for obj in obj_set:
            if not (serializer := self.serializer_map.get(type(obj))):
                LOGGER.debug("No serializer found for object of type %s", type(obj))
                continue
            serialized: Dict[str, Any] = {}
            serializer(obj, serialized)
            result.append(serialized)
        self._queue = [] # Clear just in case
        return result

    def deserialize(self, data: Dict[str, Any]) -> Any:
        """Deserialize an object from JSON"""
        dto = NODE_ADAPTER.validate_python(data)
        return dto.to_model(self.model_map)

    def _serialize_entity(self, obj: Entity, data: Dict[str, Any]) -> None:
        """Serialize common entity fields"""
        data.update({
            "long_name": obj.long_name()
        })

    def _serialize_network_node(self, obj: NetworkNode, data: Dict[str, Any]) -> None:
        """Serialize network node"""
        self._serialize_entity(obj, data)
        verdict = obj.get_verdict(self.verdict_map)
        data.update({
            "name": obj.name,
            "description": obj.description,
            "match_priority": obj.match_priority,
            "address": obj.get_system_address().get_parseable_value(),
            "host_type": obj.host_type,
            "status": obj.status.value,
            "verdict": verdict.value,
            "external_activity": obj.external_activity.value,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        })

        for child in obj.children:
            self._queue.append(child)

        for component in obj.components:
            self._queue.append(component)

        if obj.networks:
            if not isinstance(obj, IoTSystem):
                LOGGER.warning("Only IoTSystem's networks are currently supported for serialization")
            else:
                for network in obj.networks:
                    if network.name == "local":
                        self._queue.append(network)

    def _serialize_addressable(self, obj: Addressable, data: Dict[str, Any]) -> None:
        """Serialize addressable"""
        self._serialize_network_node(obj, data)
        addresses = [a.get_parseable_value() for a in obj.addresses if not a.is_tag()]
        if (tag := obj.get_tag()) and not isinstance(obj, Service):
            addresses.append(tag.get_parseable_value())
        data.update({
            "addresses": addresses,
            "parent_address": obj.parent.get_system_address().get_parseable_value(),
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

        # Add connections at the end of the queue
        for connection in obj.get_connections():
            self._queue.append(connection)

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
        self._serialize_entity(obj, data)
        data.update({
            "name": obj.name,
            "address": obj.get_system_address().get_parseable_value(),
            "status": obj.status.value,
            "parent_address": obj.entity.get_system_address().get_parseable_value()
        })

    def _serialize_software(self, obj: Software, data: Dict[str, Any]) -> None:
        """Serialize software"""
        self._serialize_node_component(obj, data)
        data.update({
            "type": "sw",
            "components": [{
                "key": key,
                "name": component.name,
                "version": component.version
            } for key, component in obj.components.items()],
            "permissions": list(obj.permissions)
        })

    def _serialize_cookies(self, obj: Cookies, data: Dict[str, Any]) -> None:
        """Serialize cookies"""
        self._serialize_node_component(obj, data)
        data.update({
            "type": "cookies",
            "cookies": {
                key: {
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "explanation": cookie.explanation
                } for key, cookie in obj.cookies.items()
            }
        })

    def _serialize_connection(self, obj: Connection, data: Dict[str, Any]) -> None:
        """Serialize connection"""
        data.update({
            "type": "connection",
            "name": obj.target.name,
            "long_name": obj.long_name(),
            "address": obj.get_system_address().get_parseable_value(),
            "source_address": obj.source.get_system_address().get_parseable_value(),
            "target_address": obj.target.get_system_address().get_parseable_value(),
            "con_type": obj.con_type.value,
            "status": obj.status.value,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        })

    def _serialize_network(self, obj: Network, data: Dict[str, Any]) -> None:
        """Serialize network"""
        if obj.ip_network:
            data.update({
                "type": "network",
                "name": obj.name,
                "address": f"network={obj.ip_network.exploded}",
                "parent_address": "" # Currently only the serialization of the IoTSystem's network is supported
            })


class BaseDTO(BaseModel):
    """Base DTO"""
    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
        str_strip_whitespace=True
    )


class PropertyDTO(BaseDTO):
    """DTO for a single property"""
    verdict: Optional[Verdict] = None
    set: List[PropertyKey] = []
    exp: DescriptionType

    @field_validator("set", mode="after")
    @classmethod
    def validate_set(cls, set_list: List[PropertyKey]) -> List[PropertyKey]:
        """Validate length of each PropertyKey"""
        for key in set_list:
            if len(str(key)) > 100:
                raise ValueError("Property key too long")
        return set_list

    def populate(self, model: NetworkNode | Connection | Flow, key: PropertyKey) -> None:
        """Populate a model's properties from this DTO"""
        if self.verdict:
            model.properties[key] = PropertyVerdictValue(self.verdict, self.exp)
        else:
            model.properties[key] = PropertySetValue(set(self.set), self.exp)


class EntityDTO(BaseDTO):
    """DTO for Entity"""
    long_name: LongNameType


class NetworkNodeDTO(EntityDTO):
    """DTO for NetworkNode"""
    name: NameType
    description: DescriptionType
    match_priority: MatchPriorityType
    address: SystemAddressType
    host_type: HostType
    status: Status
    verdict: Optional[Verdict] = None
    external_activity: ExternalActivity
    properties: Dict[PropertyKey, PropertyDTO]

    def populate(self, model: NetworkNode, model_map: Dict[str, Any]) -> None:
        """Populate a network node model from this DTO"""
        model.name = self.name
        model.description = self.description
        model.match_priority = self.match_priority
        model.host_type = self.host_type
        model.status = self.status
        model.external_activity = self.external_activity
        for key, property_dto in self.properties.items():
            property_dto.populate(model, key)
        if not isinstance(model, IoTSystem):
            model.get_system().originals.add(model)
        model_map[self.address] = model


class IgnoreRuleDTO(BaseDTO):
    """DTO for IgnoreRule"""
    properties: List[str]
    at: List[SystemAddressType]
    explanation: DescriptionType

    @field_validator("properties")
    @classmethod
    def validate_properties(cls, properties: List[str]) -> List[str]:
        """Validate property keys"""
        validate_property_keys(properties)
        return properties


class IgnoreRulesDTO(BaseDTO):
    """DTO for IgnoreRules"""
    rules: Dict[NameType, List[IgnoreRuleDTO]] # file type, related rules


class IoTSystemDTO(NetworkNodeDTO):
    """DTO for IoTSystem"""
    type: Literal["system"] = "system"
    upload_tag: UploadTagType
    ignore_rules: IgnoreRulesDTO

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


class AddressableDTO(NetworkNodeDTO):
    """DTO for Addressable"""
    addresses: List[AnyAddress]
    parent_address: SystemAddressType
    any_host: bool

    def populate(self, model: NetworkNode, model_map: Dict[str, Any]) -> None:
        """Populate an addressable model from this DTO"""
        super().populate(model, model_map)
        assert isinstance(model, Addressable)
        model.addresses = set(self.addresses)
        model.parent = model_map[self.parent_address]
        model.parent.children.append(model)
        model.any_host = self.any_host


class HostDTO(AddressableDTO):
    """DTO for Host"""
    type: Literal["host"] = "host"
    ignore_name_requests: List[DNSName] = []

    def to_model(self, model_map: Dict[str, Any]) -> Host:
        """Create and populate a Host from this DTO"""
        model = Host(parent=model_map[self.parent_address], name=self.name)
        super().populate(model, model_map)
        for dns_name in self.ignore_name_requests:
            model.ignore_name_requests.add(dns_name)
        return model


class ServiceDTO(AddressableDTO):
    """DTO for Service"""
    type: Literal["service"] = "service"
    protocol: Optional[Protocol]
    con_type: ConnectionType
    authentication: bool
    client_side: bool
    multicast_target: Optional[MulticastTarget] = None
    port_range: Optional[PortRange] = None
    reply_from_other_address: bool

    def populate(self, model: NetworkNode, model_map: Dict[str, Any]) -> None:
        """Populate a service model from this DTO"""
        super().populate(model, model_map)
        assert isinstance(model, Service)
        model.protocol = self.protocol
        model.con_type = self.con_type
        model.authentication = self.authentication
        model.client_side = self.client_side
        model.multicast_target = self.multicast_target
        model.port_range = self.port_range
        model.reply_from_other_address = self.reply_from_other_address

    def to_model(self, model_map: Dict[str, Any]) -> Service:
        """Create and populate a Service from this DTO"""
        model = Service(name=self.name, parent=model_map[self.parent_address])
        self.populate(model, model_map)
        return model


class DHCPServiceDTO(ServiceDTO):
    """DTO for DHCPService"""
    type: Literal["dhcp-service"] = "dhcp-service"  # type: ignore[assignment]

    def to_model(self, model_map: Dict[str, Any]) -> DHCPService:
        """Create and populate a DHCPService from this DTO"""
        model = DHCPService(parent=model_map[self.parent_address], name=self.name)
        super().populate(model, model_map)
        return model


class DNSServiceDTO(ServiceDTO):
    """DTO for DNSService"""
    type: Literal["dns-service"] = "dns-service"  # type: ignore[assignment]

    def to_model(self, model_map: Dict[str, Any]) -> DNSService:
        """Create and populate a DNSService from this DTO"""
        model = DNSService(parent=model_map[self.parent_address], name=self.name)
        super().populate(model, model_map)
        return model


class NodeComponentDTO(EntityDTO):
    """DTO for node component fields and population"""
    name: NameType
    address: SystemAddressType
    status: Status
    parent_address: SystemAddressType

    def populate(self, model: NodeComponent, model_map: Dict[str, Any]) -> None:
        """Populate a node component model from this DTO"""
        model_map[self.address] = model
        model.status = self.status
        model.entity.add_component(model)


class SoftwareDTO(NodeComponentDTO):
    """DTO for Software"""
    type: Literal["sw"] = "sw"
    components: List["SoftwareComponentDTO"]
    permissions: List[MobilePermissions] = []

    def to_model(self, model_map: Dict[str, Any]) -> Software:
        """Create and populate a Software from this DTO"""
        model = Software(entity=model_map[self.parent_address], name=self.name)
        super().populate(model, model_map)
        for component_dto in self.components:
            model.components[component_dto.key] = SoftwareComponent(
                name=component_dto.name,
                version=component_dto.version
            )
        model.permissions = {p.value for p in self.permissions}
        return model


class SoftwareComponentDTO(BaseDTO):
    """DTO for SoftwareComponent"""
    key: NameType
    name: NameType
    version: str = Field("", max_length=50)


class CookieDTO(NodeComponentDTO):
    """DTO for Cookies"""
    type: Literal["cookies"] = "cookies"
    cookies: Dict[NameType, "CookieDataDTO"]

    def to_model(self, model_map: Dict[str, Any]) -> Cookies:
        """Create and populate a Cookies from this DTO"""
        model = Cookies(entity=model_map[self.parent_address], name=self.name)
        super().populate(model, model_map)
        for key, cookie_dto in self.cookies.items():
            model.cookies[key] = CookieData(
                domain=cookie_dto.domain,
                path=cookie_dto.path,
                explanation=cookie_dto.explanation
            )
        return model


class CookieDataDTO(BaseDTO):
    """DTO for CookieData"""
    domain: str = Field(..., min_length=1, max_length=100)
    path: str = Field(..., min_length=1, max_length=200)
    explanation: DescriptionType


class ConnectionDTO(BaseDTO):
    """DTO for Connection"""
    type: Literal["connection"] = "connection"
    name: NameType
    long_name: LongNameType
    address: SystemAddressType
    source_address: SystemAddressType
    target_address: SystemAddressType
    con_type: ConnectionType
    status: Status
    properties: Dict[PropertyKey, PropertyDTO]

    def to_model(self, model_map: Dict[str, Any]) -> Connection:
        """Create a Connection from this DTO"""
        connection = Connection(
            source=model_map[self.source_address],
            target=model_map[self.target_address]
        )
        connection.source.get_parent_host().connections.append(connection)
        connection.target.get_parent_host().connections.append(connection)

        connection.status = self.status
        connection.con_type = self.con_type
        for key, property_dto in self.properties.items():
            property_dto.populate(connection, key)

        model_map[self.address] = connection
        return connection


class NetworkDTO(BaseDTO):
    """DTO for Networks"""
    type: Literal["network"] = "network"
    name: Literal["local"] = "local" # Currently only the IoTSystem's local network is supported
    parent_address: Literal[""] = ""
    address: IPvAnyNetwork

    @field_validator("address", mode="before")
    @classmethod
    def parse_address(cls, value: str) -> str:
        """Strip "network=" prefix from address"""
        if isinstance(value, str) and value.startswith("network="):
            return value.removeprefix("network=")
        return value

    def to_model(self, model_map: Dict[str, Any]) -> Network: # pylint: disable=unused-argument
        """Create a Network from this DTO"""
        ip_network = ipaddress.ip_network(self.address) if self.address else None
        network = Network(name=self.name, ip_network=ip_network)
        if isinstance(parent := model_map[self.parent_address], IoTSystem):
            parent.networks = [network]
        # Network never applied anywhere if the parent was not an IoTSystem
        return network


UnionDTO = Annotated[
    Union[
        IoTSystemDTO,
        HostDTO,
        ServiceDTO,
        DHCPServiceDTO,
        DNSServiceDTO,
        SoftwareDTO,
        CookieDTO,
        ConnectionDTO,
        NetworkDTO
    ],
    Field(discriminator="type")
]
NODE_ADAPTER: TypeAdapter[UnionDTO] = TypeAdapter(UnionDTO)
