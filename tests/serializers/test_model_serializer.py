import pytest

from toolsaf.main import HTTP, DHCP, DNS
from toolsaf.common.android import MobilePermissions
from toolsaf.common.address import DNSName, Protocol, Network
from toolsaf.common.basics import ExternalActivity, HostType, ConnectionType
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.verdict import Verdict
from toolsaf.core.components import Software, SoftwareComponent, Cookies, CookieData
from toolsaf.core.model import IoTSystem, Host, Service, Connection
from toolsaf.core.serializer.model_serializer import SystemSerializer
from toolsaf.core.services import DHCPService, DNSService
from tests.test_model import Setup


def test_iot_system_dto():
    setup = Setup()
    setup.system.system.name = "Test System"
    setup.system.system.description = "desc"
    setup.system.tag("test-tag")
    device = setup.system.device("Device 1")
    setup.system.ignore("pcap-0").at(device).properties("verdict:key", "verdict:key2").because("exp1")
    setup.system.ignore("pcap-1").properties("verdict:key3").because("exp2")
    setup.system.system.ignore_rules = setup.system.ignore_backend.get_rules()
    setup.system.system.properties[PropertyKey.parse("verdict:key")] = PropertyVerdictValue(Verdict.PASS)
    setup.system.system.properties[PropertyKey.parse("set:key")] = PropertySetValue({PropertyKey.parse("sub:key")})

    records = SystemSerializer().serialize(setup.system.system)
    serialized = records[0]
    ignore_rules = serialized.pop("ignore_rules")
    assert serialized == {
        "long_name": "Test System",
        "name": "Test System",
        "description": "desc",
        "match_priority": 0,
        "address": "",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.BANNED.value,
        "properties": {"verdict:key": {"verdict": Verdict.PASS.value}, "set:key": {"set": ["sub:key"]}},
        "type": "system",
        "upload_tag": "test-tag"
    }
    assert "pcap-0" in ignore_rules["rules"] and "pcap-1" in ignore_rules["rules"]
    assert len(ignore_rules["rules"]["pcap-0"]) == 1
    assert len(ignore_rules["rules"]["pcap-1"]) == 1
    assert ignore_rules["rules"]["pcap-0"][0]["at"] == ["Device_1"]
    assert ignore_rules["rules"]["pcap-0"][0]["explanation"] == "exp1"
    assert sorted(ignore_rules["rules"]["pcap-0"][0]["properties"]) == ["verdict:key", "verdict:key2"]
    assert ignore_rules["rules"]["pcap-1"][0]["at"] == []
    assert ignore_rules["rules"]["pcap-1"][0]["explanation"] == "exp2"
    assert ignore_rules["rules"]["pcap-1"][0]["properties"] == ["verdict:key3"]

    iot_system = SystemSerializer().deserialize(serialized | {"ignore_rules": ignore_rules})
    assert isinstance(iot_system, IoTSystem)
    assert iot_system.name == setup.system.system.name
    assert iot_system.upload_tag == setup.system.system.upload_tag
    assert setup.system.system.ignore_rules == iot_system.ignore_rules
    assert iot_system.properties == setup.system.system.properties


def test_host_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    host = device.entity
    host.ignore_name_requests.add(DNSName("test.com"))
    host.ignore_name_requests.add(DNSName("test2.com"))
    host.properties[PropertyKey.parse("verdict:key")] = PropertyVerdictValue(Verdict.PASS)
    host.properties[PropertyKey.parse("set:key")] = PropertySetValue({PropertyKey.parse("sub:key")})

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_system = records[0]
    s_host = records[1]
    ignore_name_reqs = s_host.pop("ignore_name_requests")
    assert records[1] == {
        "long_name": "Device 1",
        "name": "Device 1",
        "description": "Internet Of Things device",
        "match_priority": 10,
        "address": "Device_1",
        "host_type": HostType.DEVICE.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.PASSIVE.value,
        "properties": {"verdict:key": {"verdict": Verdict.PASS.value}, "set:key": {"set": ["sub:key"]}},
        "addresses": ["Device_1"],
        "parent_address": "",
        "any_host": False,
        "type": "host"
    }
    assert sorted(ignore_name_reqs) == ["test.com", "test2.com"]

    new_system = serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host | {"ignore_name_requests": ignore_name_reqs})
    assert isinstance(new_host, Host)
    assert new_host.name == host.name
    assert new_host.ignore_name_requests == host.ignore_name_requests
    assert new_host.parent == new_system
    assert new_host in new_system.children
    assert new_host.properties == host.properties


def test_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / HTTP).entity
    service.properties[PropertyKey.parse("verdict:key")] = PropertyVerdictValue(Verdict.PASS)
    service.properties[PropertyKey.parse("set:key")] = PropertySetValue({PropertyKey.parse("sub:key")})

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[2] == {
        "long_name": "Device 1 HTTP:80",
        "name": "HTTP:80",
        "description": "",
        "match_priority": 10,
        "address": "Device_1/tcp:80",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.PASSIVE.value,
        "properties": {"verdict:key": {"verdict": Verdict.PASS.value}, "set:key": {"set": ["sub:key"]}},
        "addresses": ["*/tcp:80"],
        "parent_address": "Device_1",
        "any_host": False,
        "type": "service",
        "protocol": Protocol.HTTP.value,
        "con_type": ConnectionType.UNKNOWN.value,
        "authentication": False,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": False
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_host = deserialized[1]
    new_service = deserialized[2]

    assert isinstance(new_service, Service)
    assert new_service.name == service.name
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host
    assert new_service.properties == service.properties


def test_dhcp_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DHCP).entity
    service.properties[PropertyKey.parse("verdict:key")] = PropertyVerdictValue(Verdict.PASS)
    service.properties[PropertyKey.parse("set:key")] = PropertySetValue({PropertyKey.parse("sub:key")})

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[2] == {
        "long_name": "Device 1 DHCP",
        "name": "DHCP",
        "description": "DHCP service",
        "match_priority": 10,
        "address": "Device_1/udp:67",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.UNLIMITED.value,
        "properties": {"verdict:key": {"verdict": Verdict.PASS.value}, "set:key": {"set": ["sub:key"]}},
        "addresses": ["*/udp:67"],
        "parent_address": "Device_1",
        "any_host": False,
        "type": "dhcp-service",
        "protocol": None,
        "con_type": ConnectionType.ADMINISTRATIVE.value,
        "authentication": False,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": True
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_host = deserialized[1]
    new_service = deserialized[2]

    assert isinstance(new_service, DHCPService)
    assert new_service.name == service.name
    assert new_service.description == service.description
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host
    assert new_service.properties == service.properties


def test_dns_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DNS).entity
    service.properties[PropertyKey.parse("verdict:key")] = PropertyVerdictValue(Verdict.PASS)
    service.properties[PropertyKey.parse("set:key")] = PropertySetValue({PropertyKey.parse("sub:key")})

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[2] == {
        "long_name": "Device 1 DNS",
        "name": "DNS",
        "description": "",
        "match_priority": 10,
        "address": "Device_1/udp:53",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.OPEN.value,
        "properties": {"verdict:key": {"verdict": Verdict.PASS.value}, "set:key": {"set": ["sub:key"]}},
        "addresses": ["*/udp:53"],
        "parent_address": "Device_1",
        "any_host": False,
        "type": "dns-service",
        "protocol": None,
        "con_type": ConnectionType.ADMINISTRATIVE.value,
        "authentication": False,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": False
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_host = deserialized[1]
    new_service = deserialized[2]

    assert isinstance(new_service, DNSService)
    assert new_service.name == service.name
    assert new_service.description == service.description
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.authentication == service.authentication
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host
    assert new_service.properties == service.properties


def test_software_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    software = device.software("Test Software").sw
    software.components = {
        "tc": SoftwareComponent("test-component", "1.0"),
        "tc2": SoftwareComponent("test-component2", "2.0"),
    }
    software.permissions.add(MobilePermissions.CALLS.value)

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[2] == {
        "long_name": "Test Software",
        "name": "Test Software",
        "address": "Device_1&software=Test_Software",
        "status": "Expected",
        "parent_address": "Device_1",
        "type": "sw",
        "components": [
            {"key": "tc", "name": "test-component", "version": "1.0"},
            {"key": "tc2", "name": "test-component2", "version": "2.0"},
        ],
        "permissions": [MobilePermissions.CALLS.value]
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_host = deserialized[1]
    new_software = deserialized[2]

    assert isinstance(new_software, Software)
    assert new_software.name == software.name
    assert new_software.components == software.components
    assert new_software.permissions == software.permissions
    assert new_software.entity == new_host


def test_cookies_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    cookies = Cookies(entity=device.entity, name="Cookies")
    device.entity.add_component(cookies)
    cookies.cookies["a"] = CookieData(domain="example.com", path="/app", explanation="cookie-a")
    cookies.cookies["b"] = CookieData(domain="example.com", path="/", explanation="cookie-b")

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[2] == {
        "long_name": "Cookies",
        "name": "Cookies",
        "address": "Device_1&cookies=Cookies",
        "status": "Expected",
        "parent_address": "Device_1",
        "type": "cookies",
        "cookies": {
            "a": {"domain": "example.com", "path": "/app", "explanation": "cookie-a"},
            "b": {"domain": "example.com", "path": "/", "explanation": "cookie-b"},
        }
    }

    deserialize = [serializer.deserialize(record) for record in records]
    new_host = deserialize[1]
    new_cookies = deserialize[2]
    assert isinstance(new_cookies, Cookies)
    assert new_cookies.name == cookies.name
    assert new_cookies.cookies == cookies.cookies
    assert new_cookies.entity == new_host


def test_connection_dto():
    setup = Setup()
    device1 = setup.system.device("Device 1")
    device2 = setup.system.device("Device 2")
    connection = (device1 >> device2 / HTTP).connection
    connection.properties[PropertyKey.parse("verdict:key")] = PropertyVerdictValue(Verdict.PASS)
    connection.properties[PropertyKey.parse("set:key")] = PropertySetValue({PropertyKey.parse("sub:key")})

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_connection = records[-1]
    assert s_connection == {
        "type": "connection",
        "name": "HTTP:80",
        "long_name": "Device 1 => Device 2 HTTP:80",
        "address": "source=Device_1&target=Device_2/tcp:80",
        "source_address": "Device_1",
        "target_address": "Device_2/tcp:80",
        "con_type": ConnectionType.UNKNOWN.value,
        "status": "Expected",
        "properties": {"verdict:key": {"verdict": Verdict.PASS.value}, "set:key": {"set": ["sub:key"]}},
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_connection = deserialized[-1]
    assert isinstance(new_connection, Connection)
    assert new_connection.con_type == connection.con_type
    assert new_connection.source == deserialized[1]
    assert new_connection.target == deserialized[3]
    assert new_connection.properties == connection.properties


def test_network_dto():
    setup = Setup()
    network = setup.system.network(ip_mask="10.42.0.0/16").network
    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_network = records[-1]
    assert s_network == {
        "type": "network",
        "name": "local",
        "address": "network=10.42.0.0/16",
        "parent_address": ""
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_system = deserialized[0]
    new_network = deserialized[1]
    assert new_network.name == network.name
    assert new_network.ip_network == network.ip_network
    assert [new_network] == new_system.networks


def test_network_dto_non_iot_system_networks_not_serialized():
    setup = Setup()
    network = setup.system.network("VPN", ip_mask="10.43.0.0/16")
    setup.system.device("Device 1").in_networks(network).ip("10.43.0.5").entity
    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)

    assert network.network not in setup.system.system.networks
    for record in records:
        if record["type"] == "network":
            assert record["address"] != "network=10.43.0.0/16"


def test_lazy_load_deserialization():
    setup = Setup()
    device1 = setup.system.device("Device 1")
    device2 = setup.system.device("Device 2")
    backend1 = setup.system.backend("Backend 1").serve(HTTP)
    device1 >> device2 / HTTP
    device2 >> backend1 / HTTP

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    out_of_order = [
        records[7], records[5], records[4], records[8],
        records[1], records[3], records[0], records[6], records[2]
    ]

    deserialized = serializer.deserialize_list(out_of_order)
    assert isinstance(deserialized[0], IoTSystem)
    assert isinstance(deserialized[1], Host)
    assert isinstance(deserialized[2], Host)
    assert isinstance(deserialized[3], Service)
    assert isinstance(deserialized[4], Connection)
    assert isinstance(deserialized[5], Host)
    assert isinstance(deserialized[6], Service)
    assert isinstance(deserialized[7], Connection)
    assert isinstance(deserialized[8], Network)


def test_deserialize_list_missing_address():
    serializer = SystemSerializer()
    with pytest.raises(ValueError, match="Each item must have an address field"):
        serializer.deserialize_list([{"type": "host", "name": "Host without address"}])
