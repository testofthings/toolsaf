"""Model serializers"""
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel, ConfigDict, model_validator, ValidationInfo

from toolsaf.common.basics import Status, ExternalActivity, HostType, ConnectionType
from toolsaf.common.verdict import Verdict
from toolsaf.common.address import Protocol
from toolsaf.common.property import PropertyKey
from toolsaf.core.model import (
    NetworkNode, IoTSystem, Addressable, Host, Service,
    NodeComponent, Connection
)
from toolsaf.core.ignore_rules import IgnoreRules, IgnoreRule
from toolsaf.core.services import DHCPService, DNSService
from toolsaf.core.components import Software, SoftwareComponent


class EpicSerializer:
    """Serializes the whole model to JSON"""
    def __init__(self):
        self.model_map: Dict[str, Any] = {} # sys_addr, model object
        self.verdict_map: Dict[str, Verdict] = {} # sys_addr, verdict

    def serialize(self, obj: Any) -> Dict[str, Any]:
        """Serialize an object to JSON"""
        match obj:
            case IoTSystem():
                serialized = IoTSystemOutDTO.model_validate(obj).model_dump()

            case Host():
                serialized = HostOutDTO.model_validate(obj).model_dump()

            case DHCPService():
                serialized = DHCPServiceOutDTO.model_validate(obj).model_dump()

            case DNSService():
                serialized = DNSServiceOutDTO.model_validate(obj).model_dump()

            case Service():
                serialized = ServiceOutDTO.model_validate(obj).model_dump()

            case Software():
                serialized = SoftwareOutDTO.model_validate(obj).model_dump()

            case Connection():
                serialized = ConnectionOutDTO.model_validate(obj).model_dump()

            case _:
                raise ValueError(f"Unsupported object type: {type(obj)}")

        self.model_map[serialized["system_address"]] = obj
        return serialized

    def deserialize(self, data: Dict[str, Any]) -> Any:
        """Deserialize an object from JSON"""

        verdict_map = {"verdict_map": self.verdict_map}

        match data.get("type"):
            case "system":
                dto = IoTSystemInDTO.model_validate(data, context=verdict_map)

                system = IoTSystem(name=dto.name)
                system.upload_tag = dto.upload_tag
                system.ignore_rules = IgnoreRules()

                for file_type, rules in dto.ignore_rules.rules.items():
                    system.ignore_rules.rules[file_type] = [IgnoreRule(
                        file_type=file_type,
                        properties={PropertyKey.parse(p) for p in rule.properties},
                        at=set(rule.at),
                        explanation=rule.explanation
                    ) for rule in rules]

                return system

            case "connection":
                return ConnectionInDTO.model_validate(data)
                #return Connection(#Resolve addresses)


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

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: NetworkNode, info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        expected = obj.get_expected_verdict(None)
        verdict_map = (info.context or {}).get("verdict_map", {})

        return {
            'name': obj.name,
            'description': obj.description,
            'match_priority': obj.match_priority,
            'system_address': obj.get_system_address().get_parseable_value(),
            'long_name': obj.long_name(),
            'host_type': obj.host_type,
            'status': obj.status,
            "expected": expected.value if expected else None,
            "verdict": obj.get_verdict(verdict_map),
            "external_activity": obj.external_activity,
            "properties": {k.get_name(): k.get_value_json(v, {}) for k, v in obj.properties.items()}
        }


class NetworkNodeInDTO(BaseModel):
    """Deserializes network nodes from JSON"""
    model_config = ConfigDict(from_attributes=True)

    name: str
    description: str
    match_priority: int
    system_address: str
    long_name: str
    host_type: HostType
    status: Status
    expected: Optional[Verdict] = None
    external_activity: ExternalActivity
    properties: Dict[str, Any] = {}


class IgnoreRuleOutDTO(BaseModel):
    """Serializes ignore rules to JSON"""
    model_config = ConfigDict(from_attributes=True)

    properties: List[str]
    at: List[str]
    explanation: str

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: IgnoreRule) -> Dict[str, Any]:
        """FIXME"""
        return {
            "properties": [p.get_name() for p in obj.properties],
            "at": list(obj.at),
            "explanation": obj.explanation
        }


class IgnoreRuleInDTO(BaseModel):
    """Deserializes ignore rules from JSON"""
    model_config = ConfigDict(from_attributes=True)

    properties: List[str]
    at: List[str]
    explanation: str


class IgnoreRulesOutDTO(BaseModel):
    """Serializes ignore rules to JSON"""
    model_config = ConfigDict(from_attributes=True)

    rules: Dict[str, List[IgnoreRuleOutDTO]] # file type, related rules

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: IgnoreRules) -> Dict[str, Any]:
        """FIXME"""
        rules = {}
        for file_type, file_rules in obj.rules.items():
            rules[file_type] = file_rules
        return {"rules": rules}


class IgnoreRulesInDTO(BaseModel):
    """Deserializes ignore rules from JSON"""
    model_config = ConfigDict(from_attributes=True)

    rules: Dict[str, List[IgnoreRuleInDTO]] # file type, related rules


class IoTSystemOutDTO(NetworkNodeOutDTO):
    """Serializes IoT systems to JSON"""
    type: str = "system"
    upload_tag: str
    ignore_rules: IgnoreRulesOutDTO

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: IoTSystem, info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        return super().extract_data(obj, info) | {
            "upload_tag": obj.upload_tag,
            "ignore_rules": obj.ignore_rules
        }


class IoTSystemInDTO(NetworkNodeInDTO):
    """Deserializes IoT systems from JSON"""
    model_config = ConfigDict(from_attributes=True)

    type: str = "system"
    upload_tag: str
    ignore_rules: IgnoreRulesInDTO


class AddressableOutDTO(NetworkNodeOutDTO):
    """Serializes addressable entities to JSON"""
    addresses: List[str]
    any_host: bool

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: Addressable, info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
        tag = obj.get_tag()
        addresses = [a.get_parseable_value() for a in obj.addresses if not a.is_tag()]
        if tag and not isinstance(obj, Service):
            addresses += [tag.get_parseable_value()]

        data = super().extract_data(obj, info)
        data |= {
            "addresses": addresses,
            "any_host": obj.any_host
        }
        return data


class HostOutDTO(AddressableOutDTO):
    """Serializes hosts to JSON"""
    type: str = "host"
    ignore_name_requests: List[str]

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: Host, info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
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

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: Service, info: ValidationInfo) -> Dict[str, Any]:
        """FIXME"""
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

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: NodeComponent) -> Dict[str, Any]:
        """FIXME"""
        return {
            'name': obj.name,
            "system_address": obj.get_system_address().get_parseable_value(),
            'status': obj.status,
            'long_name': obj.long_name(),
        }


class SoftwareOutDTO(NodeComponentOutDTO):
    """Serializes software components to JSON"""
    type: str = "software"
    components: List["SoftwareComponentOutDTO"]
    permissions: List[str]

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: Software) -> Dict[str, Any]:
        """FIXME"""
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

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: Tuple[str, SoftwareComponent]) -> Dict[str, Any]:
        """FIXME"""
        key, component = obj
        return {
            "key": key,
            'name': component.name,
            'version': component.version,
        }


class ConnectionOutDTO(BaseModel):
    """Serializes connections to JSON"""
    model_config = ConfigDict(from_attributes=True)

    type: str = "connection"
    system_address: str
    source_system_address: str
    target_system_address: str
    status: str
    # Really required?
    source_long_name: str
    target_long_name: str

    @model_validator(mode='before')
    @classmethod
    def extract_data(cls, obj: Connection) -> Dict[str, Any]:
        """FIXME"""
        return {
            'system_address': obj.get_system_address().get_parseable_value(),
            'source_system_address': obj.source.get_system_address().get_parseable_value(),
            'target_system_address': obj.target.get_system_address().get_parseable_value(),
            'status': obj.status.value,
            'source_long_name': obj.source.long_name(),
            'target_long_name': obj.target.long_name(),
        }


class ConnectionInDTO(BaseModel):
    """Deserializes connections from JSON"""
    model_config = ConfigDict(from_attributes=True)

    system_address: str
    source_system_address: str
    target_system_address: str
    status: str
