import ipaddress

import pytest
from pydantic import ValidationError

from toolsaf.main import HTTP, DHCP, DNS, SSH
from toolsaf.common.android import MobilePermissions
from toolsaf.common.address import DNSName, Protocol, Network
from toolsaf.common.basics import ExternalActivity, HostType, ConnectionType
from toolsaf.common.property import PropertyKey, PropertyVerdictValue, PropertySetValue
from toolsaf.common.verdict import Verdict
from toolsaf.core.components import Software, SoftwareComponent, Cookies, CookieData
from toolsaf.core.model import IoTSystem, Host, Service, Connection
from toolsaf.core.serializer.model_serializer import NetworkDTO, SystemSerializer
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

    records = SystemSerializer().serialize(setup.system.system)
    serialized = records[1]
    ignore_rules = serialized.pop("ignore_rules")
    assert serialized == {
        "long_name": "Test System",
        "name": "Test System",
        "description": "desc",
        "match_priority": 0,
        "address": "",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "external_activity": ExternalActivity.BANNED.value,
        "networks": ["default"],
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

    deserializer = SystemSerializer()
    deserializer.deserialize(records[0]) # The default network, referred to by the system
    iot_system = deserializer.deserialize(serialized | {"ignore_rules": ignore_rules})
    assert isinstance(iot_system, IoTSystem)
    assert iot_system.name == setup.system.system.name
    assert iot_system.upload_tag == setup.system.system.upload_tag
    assert setup.system.system.ignore_rules == iot_system.ignore_rules


def test_host_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    host = device.entity
    host.ignore_name_requests.add(DNSName("test.com"))
    host.ignore_name_requests.add(DNSName("test2.com"))

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_system = records[1]
    s_host = records[2]
    ignore_name_reqs = s_host.pop("ignore_name_requests")
    assert records[2] == {
        "long_name": "Device 1",
        "name": "Device 1",
        "description": "Internet Of Things device",
        "match_priority": 10,
        "address": "Device_1",
        "host_type": HostType.DEVICE.value,
        "status": "Expected",
        "external_activity": ExternalActivity.PASSIVE.value,
        "addresses": ["Device_1"],
        "parent_address": "",
        "any_host": False,
        "type": "host"
    }
    assert sorted(ignore_name_reqs) == ["test.com", "test2.com"]

    serializer.deserialize(records[0]) # The default network
    new_system = serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host | {"ignore_name_requests": ignore_name_reqs})
    assert isinstance(new_host, Host)
    assert new_host.name == host.name
    assert new_host.ignore_name_requests == host.ignore_name_requests
    assert new_host.parent == new_system
    assert new_host in new_system.children


def test_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / HTTP).entity

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[3] == {
        "long_name": "Device 1 HTTP:80",
        "name": "HTTP:80",
        "description": "",
        "match_priority": 10,
        "address": "Device_1/tcp:80",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "external_activity": ExternalActivity.PASSIVE.value,
        "addresses": ["*/tcp:80"],
        "parent_address": "Device_1",
        "any_host": False,
        "type": "service",
        "protocol": Protocol.HTTP.value,
        "con_type": ConnectionType.UNKNOWN.value,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": False
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_host = deserialized[2]
    new_service = deserialized[3]

    assert isinstance(new_service, Service)
    assert new_service.name == service.name
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host


def test_dhcp_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DHCP).entity

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[3] == {
        "long_name": "Device 1 DHCP",
        "name": "DHCP",
        "description": "DHCP service",
        "match_priority": 10,
        "address": "Device_1/udp:67",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "external_activity": ExternalActivity.UNLIMITED.value,
        "addresses": ["*/udp:67"],
        "parent_address": "Device_1",
        "any_host": False,
        "type": "dhcp-service",
        "protocol": None,
        "con_type": ConnectionType.ADMINISTRATIVE.value,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": True
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_host = deserialized[2]
    new_service = deserialized[3]

    assert isinstance(new_service, DHCPService)
    assert new_service.name == service.name
    assert new_service.description == service.description
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host


def test_dns_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DNS).entity

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[3] == {
        "long_name": "Device 1 DNS",
        "name": "DNS",
        "description": "",
        "match_priority": 10,
        "address": "Device_1/udp:53",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "external_activity": ExternalActivity.OPEN.value,
        "addresses": ["*/udp:53"],
        "parent_address": "Device_1",
        "any_host": False,
        "type": "dns-service",
        "protocol": None,
        "con_type": ConnectionType.ADMINISTRATIVE.value,
        "client_side": False,
        "multicast_target": None,
        "port_range": None,
        "reply_from_other_address": False
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_host = deserialized[2]
    new_service = deserialized[3]

    assert isinstance(new_service, DNSService)
    assert new_service.name == service.name
    assert new_service.description == service.description
    assert new_service.protocol == service.protocol
    assert new_service.con_type == service.con_type
    assert new_service.client_side == service.client_side
    assert new_service.reply_from_other_address == service.reply_from_other_address
    assert new_service.multicast_target == service.multicast_target
    assert new_service.port_range == service.port_range
    assert new_service.parent == new_host


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
    assert records[3] == {
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
    new_host = deserialized[2]
    new_software = deserialized[3]

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
    assert records[3] == {
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
    new_host = deserialize[2]
    new_cookies = deserialize[3]
    assert isinstance(new_cookies, Cookies)
    assert new_cookies.name == cookies.name
    assert new_cookies.cookies == cookies.cookies
    assert new_cookies.entity == new_host


def test_connection_dto():
    setup = Setup()
    device1 = setup.system.device("Device 1")
    device2 = setup.system.device("Device 2")
    connection = (device1 >> device2 / HTTP).connection

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
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_connection = deserialized[-1]
    assert isinstance(new_connection, Connection)
    assert new_connection.con_type == connection.con_type
    assert new_connection.source == deserialized[2]
    assert new_connection.target == deserialized[4]

def test_network_dto():
    setup = Setup()
    network = setup.system.network(ip_mask="10.42.0.0/16").network
    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_network = records[0] # Networks are serialized first
    assert s_network == {
        "type": "network",
        "name": "default",
        "address": "network=default",
        "ip_mask": "10.42.0.0/16"
    }

    deserialized = [serializer.deserialize(record) for record in records]
    new_network = deserialized[0]
    new_system = deserialized[1]
    assert isinstance(new_network, Network)
    assert new_network.name == network.name
    assert new_network.ip_network == network.ip_network
    assert [new_network] == new_system.networks


def test_network_dto_without_ip_mask():
    setup = Setup()
    network = setup.system.network("VPN").network
    setup.system.device("Device 1").in_networks(setup.system.network("VPN"))
    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    assert records[1] == {
        "type": "network",
        "name": "VPN",
        "address": "network=VPN",
        "ip_mask": None
    }

    deserialized = serializer.deserialize_list(records)
    new_network = serializer.model_map["network=VPN"]
    assert isinstance(new_network, Network)
    assert new_network.name == network.name
    assert new_network.ip_network is None
    assert serializer.model_map["Device_1"].networks == [new_network]


def test_non_iot_system_networks():
    setup = Setup()
    default = setup.system.network(ip_mask="10.42.0.0/16")
    vpn = setup.system.network("VPN", ip_mask="10.43.0.0/16")
    device = setup.system.device("Device 1").in_networks(default, vpn)
    service = (device / SSH).entity
    service.networks = [vpn.network]

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)

    # All networks of the model are serialized, before the entities referring to them
    assert [r["address"] for r in records if r["type"] == "network"] == ["network=default", "network=VPN"]
    assert records[2]["address"] == "" and records[2]["networks"] == ["default"]
    assert records[3]["address"] == "Device_1"
    assert records[3]["networks"] == ["default", "VPN"]
    assert records[4]["address"] == "Device_1/tcp:22"
    assert records[4]["networks"] == ["VPN"]

    serializer.deserialize_list(records)
    new_default = serializer.model_map["network=default"]
    new_vpn = serializer.model_map["network=VPN"]
    assert new_default.ip_network == default.network.ip_network
    assert new_vpn.ip_network == vpn.network.ip_network
    assert serializer.model_map[""].networks == [new_default]
    assert serializer.model_map["Device_1"].networks == [new_default, new_vpn]
    assert serializer.model_map["Device_1/tcp:22"].networks == [new_vpn]
    # Networks are shared between the entities referring to them
    assert serializer.model_map["Device_1"].networks[1] is new_vpn


def test_networks_of_reserialized_model():
    setup = Setup()
    default = setup.system.network(ip_mask="10.42.0.0/16")
    loopback = setup.system.network(ip_mask="127.0.0.0/8")
    setup.system.device("Device 1").in_networks(default, loopback) / SSH

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    serializer.deserialize_list(records)
    new_records = SystemSerializer().serialize(serializer.model_map[""])
    assert new_records == records


def test_node_networks_deserialized_out_of_order():
    setup = Setup()
    vpn = setup.system.network("VPN", ip_mask="10.43.0.0/16")
    setup.system.device("Device 1").in_networks(vpn)

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    # Lazy loading resolves the networks of a node before the node itself
    serializer.deserialize_list(list(reversed(records)))
    assert serializer.model_map["Device_1"].networks == [vpn.network]


def test_node_networks_missing_network_record():
    setup = Setup()
    vpn = setup.system.network("VPN", ip_mask="10.43.0.0/16")
    setup.system.device("Device 1").in_networks(vpn)

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_host = [r for r in records if r["type"] == "host"][0]
    serializer.deserialize(records[0]) # The default network
    serializer.deserialize([r for r in records if r["type"] == "system"][0])
    with pytest.raises(ValueError, match="Network 'network=VPN' must be deserialized before node 'Device_1'"):
        serializer.deserialize(s_host)


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
        records[8], records[6], records[5], records[0],
        records[2], records[4], records[1], records[7], records[3]
    ]

    deserialized = serializer.deserialize_list(out_of_order)
    assert len(deserialized) == len(records)
    expected = {
        "network=default": Network,
        "": IoTSystem,
        "Device_1": Host,
        "Device_2": Host,
        "Device_2/tcp:80": Service,
        "Backend_1": Host,
        "Backend_1/tcp:80": Service,
        "source=Device_1&target=Device_2/tcp:80": Connection,
        "source=Device_2&target=Backend_1/tcp:80": Connection
    }
    assert set(serializer.model_map) == set(expected)
    for address, model_type in expected.items():
        assert isinstance(serializer.model_map[address], model_type)


def test_deserialize_list_missing_address():
    serializer = SystemSerializer()
    with pytest.raises(ValueError, match="Each item must have an address field"):
        serializer.deserialize_list([{"type": "host", "name": "Host without address"}])


def _legacy_records():
    """Records of a security statement serialized before networks were named in their address"""
    return [
        {
            "long_name": "Legacy System", "name": "Legacy System", "description": "", "match_priority": 0,
            "address": "", "host_type": "", "status": "Expected", "verdict": "Incon", "external_activity": 0,
            "properties": {}, "ignore_rules": {"rules": {}}, "type": "system", "upload_tag": "legacy-tag"
        },
        {
            "long_name": "Device 1", "name": "Device 1", "description": "", "match_priority": 10,
            "address": "Device_1", "host_type": "Device", "status": "Expected", "verdict": "Incon",
            "external_activity": 1, "properties": {}, "addresses": ["Device_1"], "parent_address": "",
            "any_host": False, "type": "host", "ignore_name_requests": []
        },
        {
            "type": "network", "name": "default", "address": "network=10.10.0.0/24", "parent_address": ""
        }
    ]


def test_deserialize_legacy_networks():
    serializer = SystemSerializer()
    deserialized = [serializer.deserialize(record) for record in _legacy_records()]
    system, host, network = deserialized

    assert isinstance(network, Network)
    assert network.name == "default"
    assert network.ip_network == ipaddress.ip_network("10.10.0.0/24")
    # The legacy network is the network of the system it names as its parent
    assert system.networks == [network]
    assert system.get_default_network() is network
    assert host.networks == [] # Follows the system
    assert serializer.model_map["network=default"] is network

    # Legacy by e.g. -W <file>
    js = NetworkDTO.convert_legacy_address(
        {"type": "network",
         "name": "default",
         "address": "network=10.10.0.0/24",
         "parent_address": ""}
    )
    assert js == {
        "type": "network",
        "name": "default",
        "address": "network=default",
        "ip_mask": "10.10.0.0/24",
        "parent_address": "",
    }

    # Legacy with 'network=' stripped
    js = NetworkDTO.convert_legacy_address(
        {"type": "network",
         "name": "default",
         "address": "10.10.0.0/24",
         "parent_address": ""}
    )
    assert js == {
        "type": "network",
        "name": "default",
        "address": "network=default",
        "ip_mask": "10.10.0.0/24",
        "parent_address": "",
    }



def test_deserialize_list_legacy_networks():
    serializer = SystemSerializer()
    serializer.deserialize_list(_legacy_records())
    system = serializer.model_map[""]
    network = serializer.model_map["network=default"]

    assert isinstance(network, Network)
    assert network.ip_network == ipaddress.ip_network("10.10.0.0/24")
    assert system.networks == [network]
    assert serializer.model_map["Device_1"].networks == []


def test_reserialize_legacy_networks():
    serializer = SystemSerializer()
    serializer.deserialize_list(_legacy_records())
    records = SystemSerializer().serialize(serializer.model_map[""])

    # Networks of a legacy statement are serialized in the current format
    assert records[0] == {
        "type": "network",
        "name": "default",
        "address": "network=default",
        "ip_mask": "10.10.0.0/24"
    }
    assert records[1]["type"] == "system" and records[1]["networks"] == ["default"]
    # Nodes without networks of their own follow their parent, no field is written for them
    assert records[2]["type"] == "host" and "networks" not in records[2]
