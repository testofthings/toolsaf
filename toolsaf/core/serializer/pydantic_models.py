"""Model serializers"""
from typing import Dict, Any, Optional, List, Tuple, cast, TypeVar
from pydantic import BaseModel, ConfigDict, model_validator, ValidationInfo

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

NodeType = TypeVar("NodeType", bound=NetworkNode)


class EpicSerializer:
    """Serializes the whole model to JSON"""
    def __init__(self):
        self.model_map: Dict[str, Addressable] = {} # sys_addr, model object
        self.verdict_map: Dict[str, Verdict] = {} # sys_addr, verdict

    def serialize(self, obj: Any) -> Dict[str, Any]:
        """Serialize an object to JSON"""
        verdict_map = {"verdict_map": self.verdict_map}

        match obj:
            case IoTSystem():
                return IoTSystemOutDTO.model_validate(obj, context=verdict_map).model_dump()

            case Host():
                return HostOutDTO.model_validate(obj, context=verdict_map).model_dump()

            case DHCPService():
                return DHCPServiceOutDTO.model_validate(obj, context=verdict_map).model_dump()

            case DNSService():
                return DNSServiceOutDTO.model_validate(obj, context=verdict_map).model_dump()

            case Service():
                return ServiceOutDTO.model_validate(obj, context=verdict_map).model_dump()

            case Software():
                return SoftwareOutDTO.model_validate(obj).model_dump()

            case Connection():
                return ConnectionOutDTO.model_validate(obj).model_dump()

            case _:
                raise ValueError(f"Unsupported object type: {type(obj)}")

    def deserialize(self, data: Dict[str, Any]) -> Any:
        """Deserialize an object from JSON"""
        match data.get("type"):
            case "system":
                dto = IoTSystemOutDTO.model_validate(data)
                system = IoTSystem()
                self._populate_iot_system(system, dto)
                return system

            case "host":
                dto = HostOutDTO.model_validate(data)
                host = Host(parent=self.model_map[dto.parent], name=dto.name)
                self._populate_host(host, dto)
                return host

            case "service":
                dto = ServiceOutDTO.model_validate(data)
                service = Service(name=dto.name, parent=self.model_map[dto.parent])
                self._populate_service(service, dto)
                return service

            case "dhcp-service":
                dto = DHCPServiceOutDTO.model_validate(data)
                dhcp = DHCPService(parent=self.model_map[dto.parent], name=dto.name)
                self._populate_service(dhcp, dto)
                return dhcp

            case "dns-service":
                dto = DNSServiceOutDTO.model_validate(data)
                dns = DNSService(parent=self.model_map[dto.parent], name=dto.name)
                self._populate_service(dns, dto)
                return dns

            case "software":
                dto = SoftwareOutDTO.model_validate(data)
                software = Software(entity=self.model_map[dto.parent], name=dto.name)
                self._populate_software(software, dto)
                return software

            case "connection":
                dto = ConnectionOutDTO.model_validate(data)
                connection = Connection(
                    source=self.model_map[dto.source_system_address],
                    target=self.model_map[dto.target_system_address]
                )
                self._populate_connection(connection, dto)
                return connection

            case _:
                raise ValueError(f"Unsupported object type: {data.get("type")}")

    def _populate_network_node(self, obj: NetworkNode, dto: "NetworkNodeOutDTO") -> None:
        """Populate a network node with data from JSON"""
        obj.name = dto.name
        obj.description = dto.description
        obj.match_priority = dto.match_priority
        # NOTE: # long_name is not an actual property, but a function
        obj.host_type = HostType(dto.host_type)
        obj.status = Status(dto.status)
        obj.external_activity = ExternalActivity(dto.external_activity)

        for key, value in dto.properties.items():
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

        self.model_map[dto.system_address] = obj

    def _populate_addressable(self, obj: Addressable, dto: "AddressableOutDTO") -> None:
        """Populate an addressable entity with data from JSON"""
        self._populate_network_node(obj, dto)
        obj.parent = self.model_map[dto.parent]
        obj.parent.children.append(obj)
        for address in dto.addresses:
            obj.addresses.add(Addresses.parse_endpoint(address))
        obj.any_host = dto.any_host

    def _populate_iot_system(self, obj: IoTSystem, dto: "IoTSystemOutDTO") -> None:
        """Populate an IoT system with data from JSON"""
        self._populate_network_node(obj, dto)
        obj.upload_tag = dto.upload_tag

        obj.ignore_rules = IgnoreRules()
        for file_type, rules in dto.ignore_rules.rules.items():
            obj.ignore_rules.rules[file_type] = [IgnoreRule(
                file_type=file_type,
                properties={PropertyKey.parse(p) for p in rule.properties},
                at=set(rule.at),
                explanation=rule.explanation
            ) for rule in rules]

    def _populate_host(self, obj: Host, dto: "HostOutDTO") -> Host:
        """Populate a host with data from JSON"""
        self._populate_addressable(obj, dto)
        for dns_name in dto.ignore_name_requests:
            obj.ignore_name_requests.add(DNSName(dns_name))
        return obj

    def _populate_service(self, obj: Service, dto: "ServiceOutDTO") -> None:
        """Populate a service with data from JSON"""
        self._populate_addressable(obj, dto)
        obj.protocol = Protocol(dto.protocol) if dto.protocol else None
        obj.con_type = ConnectionType(dto.con_type)
        obj.authentication = dto.authentication
        obj.client_side = dto.client_side
        obj.multicast_target = MulticastTarget.parse_address_range(dto.multicast_target) if dto.multicast_target else None
        obj.port_range = PortRange.parse_port_range(dto.port_range) if dto.port_range else None
        obj.reply_from_other_address = dto.reply_from_other_address # NOTE: DELETE

    def _populate_node_component(self, obj: NodeComponent, dto: "NodeComponentOutDTO") -> None:
        """Populate a node component with data from JSON"""
        obj.name = dto.name
        obj.status = Status(dto.status)

    def _populate_software(self, obj: Software, dto: "SoftwareOutDTO") -> None:
        """Populate a software component with data from JSON"""
        self._populate_node_component(obj, dto)
        for component_dto in dto.components:
            obj.components[component_dto.key] = SoftwareComponent(
                name=component_dto.name,
                version=component_dto.version
            )
        obj.permissions = set(dto.permissions)

    def _populate_connection(self, obj: Connection, dto: "ConnectionOutDTO") -> None:
        """Populate a connection with data from JSON"""
        obj.status = Status(dto.status)



class NetworkNodeOutDTO(BaseModel):
    """Serializes network nodes to JSON"""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    name: str
    description: str
    match_priority: int
    system_address: str
    long_name: str
    host_type: HostType
    status: Status
    expected: Optional[Verdict] = None
    verdict: Optional[Verdict] = None
    external_activity: ExternalActivity
    properties: Dict[str, Any] = {}

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: NetworkNode | Dict[str, Any], info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        expected = obj.get_expected_verdict(None)
        verdict_map = (info.context or {}).get("verdict_map", {})

        return {
            "name": obj.name,
            "description": obj.description,
            "match_priority": obj.match_priority,
            "system_address": obj.get_system_address().get_parseable_value(),
            "long_name": obj.long_name(),
            "host_type": obj.host_type,
            "status": obj.status,
            "expected": expected.value if expected else None,
            "verdict": obj.get_verdict(verdict_map),
            "external_activity": obj.external_activity,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        }


class IgnoreRuleOutDTO(BaseModel):
    """Serializes ignore rules to JSON"""
    model_config = ConfigDict(from_attributes=True)

    properties: List[str]
    at: List[str]
    explanation: str

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: IgnoreRule | Dict[str, Any]) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        return {
            "properties": [p.get_name() for p in obj.properties],
            "at": list(obj.at),
            "explanation": obj.explanation
        }


class IgnoreRulesOutDTO(BaseModel):
    """Serializes ignore rules to JSON"""
    model_config = ConfigDict(from_attributes=True)

    rules: Dict[str, List[IgnoreRuleOutDTO]] # file type, related rules

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: IgnoreRules | Dict[str, Any]) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        rules = {}
        for file_type, file_rules in obj.rules.items():
            rules[file_type] = file_rules
        return {"rules": rules}


class IoTSystemOutDTO(NetworkNodeOutDTO):
    """Serializes IoT systems to JSON"""
    type: str = "system"
    upload_tag: str
    ignore_rules: IgnoreRulesOutDTO

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: IoTSystem | Dict[str, Any], info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        return super().extract_data(obj, info) | {
            "upload_tag": obj.upload_tag,
            "ignore_rules": obj.ignore_rules
        }


class AddressableOutDTO(NetworkNodeOutDTO):
    """Serializes addressable entities to JSON"""
    addresses: List[str]
    parent: str # Parent system address
    any_host: bool

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: Addressable | Dict[str, Any], info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        tag = obj.get_tag()
        addresses = [a.get_parseable_value() for a in obj.addresses if not a.is_tag()]
        if tag and not isinstance(obj, Service):
            addresses += [tag.get_parseable_value()]

        data = super().extract_data(obj, info)
        data |= {
            "addresses": addresses,
            "parent": obj.parent.get_system_address().get_parseable_value(),
            "any_host": obj.any_host
        }
        return data


class HostOutDTO(AddressableOutDTO):
    """Serializes hosts to JSON"""
    type: str = "host"
    ignore_name_requests: List[str]

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: Host | Dict[str, Any], info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        data = super().extract_data(obj, info)
        data["ignore_name_requests"] = [dns_name.name for dns_name in obj.ignore_name_requests]
        return data


class ServiceOutDTO(AddressableOutDTO):
    """Serializes services to JSON"""
    type: str = "service"
    protocol: Optional[Protocol]
    con_type: ConnectionType
    authentication: bool
    client_side: bool
    multicast_target: Optional[str]
    port_range: Optional[str]
    reply_from_other_address: bool

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: Service | Dict[str, Any], info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        data = super().extract_data(obj, info)
        data |= {
            "protocol": obj.protocol,
            "con_type": obj.con_type,
            "authentication": obj.authentication,
            "client_side": obj.client_side,
            "multicast_target": obj.multicast_target.get_parseable_value() if obj.multicast_target else None,
            "port_range": obj.port_range.get_parseable_value() if obj.port_range else None,
            "reply_from_other_address": obj.reply_from_other_address
        }
        return data


class DHCPServiceOutDTO(ServiceOutDTO):
    """Serializes DHCP services to JSON"""
    type: str = "dhcp-service"


class DNSServiceOutDTO(ServiceOutDTO):
    """Serializes DNS services to JSON"""
    type: str = "dns-service"


class NodeComponentOutDTO(BaseModel):
    """Serializes node components to JSON"""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    name: str
    system_address: str
    status: Status
    long_name: str
    parent: str # Parent system address

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: NodeComponent | Dict[str, Any]) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        return {
            "name": obj.name,
            "system_address": obj.get_system_address().get_parseable_value(),
            "status": obj.status,
            "long_name": obj.long_name(),
            "parent": obj.entity.get_system_address().get_parseable_value()
        }


class SoftwareOutDTO(NodeComponentOutDTO):
    """Serializes software components to JSON"""
    type: str = "software"
    components: List["SoftwareComponentOutDTO"]
    permissions: List[str]

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: Software | Dict[str, Any]) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        data = super().extract_data(obj)
        return data | {
            "components": [(name, component) for name, component in obj.components.items()],
            "permissions": obj.permissions
        }


class SoftwareComponentOutDTO(BaseModel):
    """Serializes software components to JSON"""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    key: str
    name: str
    version: str

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: Tuple[str, SoftwareComponent] | List[Dict[str, Any]]) -> Dict[str, Any]:
        """FIXME"""
        if not isinstance(obj, tuple):
            return obj

        key, component = obj
        return {
            "key": key,
            "name": component.name,
            "version": component.version,
        }


class ConnectionOutDTO(BaseModel):
    """Serializes connections to JSON"""
    model_config = ConfigDict(from_attributes=True)

    type: str = "connection"
    system_address: str
    source_system_address: str
    target_system_address: str
    status: str
    properties: Dict[str, Any]
    # Really required?
    source_long_name: str
    target_long_name: str

    @model_validator(mode="before")
    @classmethod
    def extract_data(cls, obj: Connection | Dict[str, Any]) -> Dict[str, Any]:
        """FIXME"""
        if isinstance(obj, dict):
            return obj

        return {
            "system_address": obj.get_system_address().get_parseable_value(),
            "source_system_address": obj.source.get_system_address().get_parseable_value(),
            "target_system_address": obj.target.get_system_address().get_parseable_value(),
            "status": obj.status.value,
            "source_long_name": obj.source.long_name(),
            "target_long_name": obj.target.long_name(),
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        }
