import pytest
from pydantic import ValidationError

from toolsaf.common.basics import Status, ExternalActivity, HostType, ConnectionType
from toolsaf.common.verdict import Verdict
from toolsaf.common.address import Protocol
from toolsaf.common.android import MobilePermissions
from toolsaf.core.serializer.model_serializer import (
    PropertyDTO, EntityDTO, NetworkNodeDTO,
    IgnoreRuleDTO, IgnoreRulesDTO, IoTSystemDTO,
    AddressableDTO, HostDTO, ServiceDTO, DHCPServiceDTO, DNSServiceDTO,
    NodeComponentDTO, SoftwareComponentDTO, SoftwareDTO,
    CookieDataDTO, CookieDTO, ConnectionDTO, NetworkDTO
)


def _validate(valid_data, key_values, dto_class):
    for key, value in key_values:
        with pytest.raises(ValidationError):
            dto_class(**{**valid_data, key: value})


def test_property_dto_invalid_values():
    key_values = [
        ("verdict", "unknown"),
        ("set", "abc"),
        ("set", [123]),
        ("set", ["a"*101]),
        ("exp", -1),
        ("exp", "a"*4001),
    ]
    _validate({}, key_values, PropertyDTO)


def test_entity_dto_invalid_values():
    key_values = [
        ("long_name", ""),
        ("long_name", "a"*301),
        ("long_name", 123)
    ]
    _validate({}, key_values, EntityDTO)


def _valid_ignore_rule():
    return {
        "properties": ["check:vunlz"],
        "verdict": Verdict.FAIL.value,
        "exp": "exp",
    }


def test_ignore_rule_dto_invalid_values():
    key_values = [
        ("properties", "abc"),
        ("properties", [123]),
        ("properties", ["a"*101]),
        ("at", "Node/fake_proto:80"),
        ("at", "Node/tcp:abc"),
        ("at", 123),
        ("explanation", "a"*4001),
        ("explanation", 123),
    ]
    _validate(_valid_ignore_rule(), key_values, IgnoreRuleDTO)


def test_ignore_rules_dto_invalid_values():
    key_values = [
        ("rules", "abc"),
        ("rules", [123]),
    ]
    _validate({}, key_values, IgnoreRulesDTO)


def _valid_properties():
    return {
        "check:vunlz": {
            "verdict": Verdict.FAIL.value,
            "exp": "exp"
        }
    }


def _valid_network_node():
    return {
        "long_name": "Node",
        "name": "Node",
        "description": "A network node",
        "match_priority": 5,
        "address": "Node",
        "host_type": HostType.DEVICE.value,
        "status": Status.EXTERNAL.value,
        "verdict": Verdict.PASS.value,
        "external_activity": ExternalActivity.BANNED.value,
        "properties": _valid_properties()
    }


def test_network_node_dto_invalid_values():
    key_values = [
        ("name", ""),
        ("name", "a"*101),
        ("name", 1),
        ("description", "a"*4001),
        ("description", 1),
        ("match_priority", -1),
        ("match_priority", 11),
        ("match_priority", "a"),
        ("address", "Node/fake_proto:80"),
        ("address", "Node/tcp:abc"),
        ("address", 1),
        ("host_type", "unknown"),
        ("host_type", 1),
        ("status", "unknown"),
        ("status", 1),
        ("verdict", "unknown"),
        ("verdict", 1),
        ("external_activity", "abc"),
        ("external_activity", 100),
    ]
    _validate(_valid_network_node(), key_values, NetworkNodeDTO)


def _valid_iot_system():
    return _valid_network_node() | {
        "type": "system",
        "upload_tag": "valid-tag",
        "ignore_rules": {"rules": {}}
    }


def test_iot_system_dto_invalid_values():
    key_values = [
        ("type", "host"),
        ("upload_tag", "ab"),
        ("upload_tag", "a"*51),
        ("upload_tag", "invalid tag"),
        ("upload_tag", "invalid/tag"),
        ("upload_tag", 123),
        ("ignore_rules", "abc")
    ]
    _validate(_valid_iot_system(), key_values, IoTSystemDTO)


def _valid_addressable():
    return _valid_network_node() | {
        "addresses": ["Node", "*/tcp:80"],
        "parent_address": "Node",
        "any_host": False
    }


def test_addressable_dto_invalid_values():
    key_values = [
        ("addresses", "abc"),
        ("addresses", [123]),
        ("addresses", ["Node/fake_proto:80"]),
        ("addresses", ["Node/tcp:abc"]),
        ("parent_address", "Node/fake_proto:80"),
        ("parent_address", "Node/tcp:abc"),
        ("parent_address", 123),
        ("any_host", "abc"),
        ("any_host", 123),
    ]
    _validate(_valid_addressable(), key_values, AddressableDTO)


def _valid_host():
    return _valid_addressable() | {
        "type": "host",
        "ignore_name_requests": ["example.com"]
    }


def test_host_dto_invalid_values():
    key_values = [
        ("type", "system"),
        ("ignore_name_requests", "abc"),
        ("ignore_name_requests", [123]),
        ("ignore_name_requests", ["a"*101]),
        ("ignore_name_requests", ["-start-with-hyphen"]),
        ("ignore_name_requests", ["end-with-hyphen-"]),
        ("ignore_name_requests", ["invalid characters!"]),
        ("ignore_name_requests", [f"{'a'*64}.com"]),
    ]
    _validate(_valid_host(), key_values, HostDTO)


def _valid_service():
    return _valid_addressable() | {
        "type": "service",
        "protocol": Protocol.TCP.value,
        "con_type": ConnectionType.ENCRYPTED.value,
        "client_side": False,
        "multicast_target": "255.255.255.255",
        "port_range": "1000-2000,2500",
        "reply_from_other_address": False
    }


def test_service_dto_invalid_values():
    key_values = [
        ("type", "host"),
        ("protocol", "unknown"),
        ("protocol", 123),
        ("con_type", "unknown"),
        ("con_type", 123),
        ("client_side", "abc"),
        ("client_side", 123),
        ("multicast_target", 123),
        ("port_range", "abc"),
        ("port_range", "1000-abc"),
        ("reply_from_other_address", "abc"),
        ("reply_from_other_address", 123),
    ]
    _validate(_valid_service(), key_values, ServiceDTO)


def _valid_dhcp_service():
    return _valid_service() | {
        "type": "dhcp-service"
    }


def test_dhcp_service_dto_invalid_values():
    key_values = [
        ("type", "service"),
    ]
    _validate(_valid_dhcp_service(), key_values, DHCPServiceDTO)


def _valid_dns_service():
    return _valid_service() | {
        "type": "dns-service"
    }


def test_dns_service_dto_invalid_values():
    key_values = [
        ("type", "service"),
    ]
    _validate(_valid_dns_service(), key_values, DNSServiceDTO)


def _valid_node_component():
    return {
        "long_name": "Node SW",
        "name": "Node SW",
        "address": "Node&software=Node_SW",
        "status": Status.EXPECTED.value,
        "parent_address": "Node"
    }


def test_node_component_dto_invalid_values():
    key_values = [
        ("name", ""),
        ("name", "a"*101),
        ("name", 123),
        ("address", "Node/fake_proto:80"),
        ("address", "Node/tcp:abc"),
        ("address", 123),
        ("status", "unknown"),
        ("status", 1),
        ("parent_address", "Node/fake_proto:80"),
        ("parent_address", "Node/tcp:abc"),
        ("parent_address", 123),
    ]
    _validate(_valid_node_component(), key_values, NodeComponentDTO)


def _valid_software_component():
    return {
        "key": "sw-key",
        "name": "Software",
        "version": "1.0",
    }


def test_software_component_dto_invalid_values():
    key_values = [
        ("key", ""),
        ("key", "a"*101),
        ("key", 123),
        ("name", ""),
        ("name", "a"*101),
        ("name", 123),
        ("version", "a"*101),
        ("version", 123),
    ]
    _validate(_valid_software_component(), key_values, SoftwareComponentDTO)


def _valid_software():
    return _valid_node_component() | {
        "type": "sw",
        "components": [_valid_software_component()],
        "permissions": [MobilePermissions.CALLS.value]
    }


def test_software_dto_invalid_values():
    key_values = [
        ("type", "host"),
        ("components", "abc"),
        ("components", [123]),
        ("permissions", "abc"),
        ("permissions", [123]),
    ]
    _validate(_valid_software(), key_values, SoftwareDTO)


def _valid_cookie_data():
    return {
        "domain": "example.com",
        "path": "/",
        "explanation": "A cookie"
    }


def test_cookie_data_dto_invalid_values():
    key_values = [
        ("domain", ""),
        ("domain", "a"*256),
        ("domain", 123),
        ("path", ""),
        ("path", "a"*1025),
        ("path", 123),
        ("explanation", "a"*4001),
        ("explanation", 123),
    ]
    _validate(_valid_cookie_data(), key_values, CookieDataDTO)


def _valid_cookie():
    return _valid_cookie_data() | {
        "type": "cookies",
        "cookies": {"cookie1": _valid_cookie_data()}
    }


def test_cookie_dto_invalid_values():
    key_values = [
        ("type", "host"),
        ("cookies", "abc"),
        ("cookies", {123: _valid_cookie_data()}),
        ("cookies", {"cookie1": "abc"}),
    ]
    _validate(_valid_cookie(), key_values, CookieDTO)


def _valid_connection():
    return {
        "type": "connection",
        "name": "Connection",
        "long_name": "Node => Node 2 TCP:80",
        "address": "source=Node_1&target=Node_2/tcp:80",
        "source_address": "Node_1",
        "target_address": "Node_2/tcp:80",
        "con_type": ConnectionType.ENCRYPTED.value,
        "status": Status.EXTERNAL.value,
        "properties": _valid_properties()
    }


def test_connection_dto_invalid_values():
    key_values = [
        ("type", "host"),
        ("name", ""),
        ("name", "a"*101),
        ("name", 123),
        ("long_name", ""),
        ("long_name", "a"*301),
        ("long_name", 123),
        ("address", "Node/fake_proto:80"),
        ("address", "Node/tcp:abc"),
        ("address", 123),
        ("source_address", "Node/fake_proto:80"),
        ("source_address", "Node/tcp:abc"),
        ("source_address", 123),
        ("target_address", "Node/fake_proto:80"),
        ("target_address", "Node/tcp:abc"),
        ("target_address", 123),
        ("con_type", "unknown"),
        ("con_type", 123),
    ]
    _validate(_valid_connection(), key_values, ConnectionDTO)


def _valid_network():
    return {
        "type": "network",
        "name": "local",
        "address": "network=127.0.0.1",
        "parent_address": ""
    }


def test_network_dto_invalid_values():
    key_values = [
        ("type", "host"),
        ("name", ""),
        ("name", "a"*101),
        ("name", 123),
        ("address", "Node/fake_proto:80"),
        ("address", "Node/tcp:abc"),
        ("parent_address", "Node/fake_proto:80"),
        ("parent_address", "Node/tcp:abc"),
        ("parent_address", 123),
    ]
    _validate(_valid_network(), key_values, NetworkDTO)
