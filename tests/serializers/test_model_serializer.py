from toolsaf.main import HTTP, DHCP, DNS
from toolsaf.common.address import DNSName, Protocol
from toolsaf.common.basics import ExternalActivity, HostType, ConnectionType
from toolsaf.common.verdict import Verdict
from toolsaf.core.components import Software, SoftwareComponent, Cookies, CookieData
from toolsaf.core.model import IoTSystem, Host, Service
from toolsaf.core.serializer.pydantic_models import SystemSerializer
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
    serialized = records[0]
    ignore_rules = serialized.pop("ignore_rules")
    assert serialized == {
        "name": "Test System",
        "description": "desc",
        "match_priority": 0,
        "system_address": "",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.BANNED.value,
        "properties": {},
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


def test_host_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    host = device.entity
    host.ignore_name_requests.add(DNSName("test.com"))
    host.ignore_name_requests.add(DNSName("test2.com"))

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_system = records[0]
    s_host = records[1]
    ignore_name_reqs = s_host.pop("ignore_name_requests")
    assert s_host == {
        "name": "Device 1",
        "description": "Internet Of Things device",
        "match_priority": 10,
        "system_address": "Device_1",
        "host_type": HostType.DEVICE.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.PASSIVE.value,
        "properties": {},
        "addresses": ["Device_1"],
        "parent": "",
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


def test_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / HTTP).entity

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_system = records[0]
    s_host = records[1]
    s_service = records[2]
    assert s_service == {
        "name": "HTTP:80",
        "description": "",
        "match_priority": 10,
        "system_address": "Device_1/tcp:80",
        "host_type": HostType.GENERIC.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.PASSIVE.value,
        "properties": {},
        "addresses": ["*/tcp:80"],
        "parent": "Device_1",
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
    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_service = serializer.deserialize(s_service)

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


def test_dhcp_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DHCP).entity

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_system = records[0]
    s_host = records[1]
    s_service = records[2]

    assert s_service == {
        "name": "DHCP",
        "description": "DHCP service",
        "match_priority": 10,
        "system_address": "Device_1/udp:67",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.UNLIMITED.value,
        "properties": {},
        "addresses": ["*/udp:67"],
        "parent": "Device_1",
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

    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_service = serializer.deserialize(s_service)

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


def test_dns_service_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    service = (device / DNS).entity

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_system = records[0]
    s_host = records[1]
    s_service = records[2]

    assert s_service == {
        "name": "DNS",
        "description": "",
        "match_priority": 10,
        "system_address": "Device_1/udp:53",
        "host_type": HostType.ADMINISTRATIVE.value,
        "status": "Expected",
        "verdict": Verdict.INCON.value,
        "external_activity": ExternalActivity.OPEN.value,
        "properties": {},
        "addresses": ["*/udp:53"],
        "parent": "Device_1",
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

    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_service = serializer.deserialize(s_service)

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


def test_software_dto():
    setup = Setup()
    device = setup.system.device("Device 1")
    software = device.software("Test Software").sw
    software.components = {
        "tc": SoftwareComponent("test-component", "1.0"),
        "tc2": SoftwareComponent("test-component2", "2.0"),
    }
    software.permissions.add("permission1")

    serializer = SystemSerializer()
    records = serializer.serialize(setup.system.system)
    s_system = records[0]
    s_host = records[1]
    s_software = records[2]

    assert s_software == {
        "name": "Test Software",
        "system_address": "Device_1&software=Test_Software",
        "status": "Expected",
        "parent": "Device_1",
        "type": "sw",
        "components": [
            {"key": "tc", "name": "test-component", "version": "1.0"},
            {"key": "tc2", "name": "test-component2", "version": "2.0"},
        ],
        "permissions": ["permission1"]
    }

    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_software = serializer.deserialize(s_software)

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
    s_system = records[0]
    s_host = records[1]
    s_cookies = records[2]

    assert s_cookies == {
        "name": "Cookies",
        "system_address": "Device_1&cookies=Cookies",
        "status": "Expected",
        "parent": "Device_1",
        "type": "cookies",
        "cookies": {
            "a": {"domain": "example.com", "path": "/app", "explanation": "cookie-a"},
            "b": {"domain": "example.com", "path": "/", "explanation": "cookie-b"},
        }
    }

    serializer.deserialize(s_system)
    new_host = serializer.deserialize(s_host)
    new_cookies = serializer.deserialize(s_cookies)

    assert isinstance(new_cookies, Cookies)
    assert new_cookies.name == cookies.name
    assert new_cookies.cookies == cookies.cookies
    assert new_cookies.entity == new_host


def test_connection_dto():
    device1 = Setup().system.device("Device 1")
    device2 = Setup().system.device("Device 2")
    connection = (device1 >> device2 / HTTP).connection

    assert SystemSerializer().serialize(connection) == [{
        "type": "connection",
        "system_address": "source=Device_1&target=Device_2/tcp:80",
        "source_system_address": "Device_1",
        "target_system_address": "Device_2/tcp:80",
        "con_type": ConnectionType.UNKNOWN.value,
        "status": "Expected",
        "properties": {},
    }]
