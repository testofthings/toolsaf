import pytest

from toolsaf.builder_backend import SystemBackend
from toolsaf.main import TLS, HTTP, TCP, ARP, IP, UDP
from toolsaf.common.android import LOCATION, NETWORK
from toolsaf.common.basics import HostType


def test_add_hosts():
    sb = SystemBackend()
    entities = [
        sb.device("Test Device").entity,
        sb.backend("Test Backend").entity,
        sb.mobile("Test Mobile").entity,
        sb.browser("Test Browser").entity,
        sb.infra("Test Infra").entity,
        sb.any("Test Any Host").entity
    ]

    assert len(sb._changes) == len(entities)
    for entity in entities:
        assert entity in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == len(entities)
    assert {
        "address": "Test_Device",
        "addresses": ["Test_Device"],
        "any_host": False,
        "description": "Internet Of Things device",
        "external_activity": 1,
        "host_type": HostType.DEVICE,
        "ignore_name_requests": [],
        "long_name": "Test Device",
        "match_priority": 10,
        "name": "Test Device",
        "parent_address": "",
        "properties": {},
        "status": "Expected",
        "type": "host",
        "verdict": "Incon",
    } in serialized


def test_add_host_with_serve_and_dns():
    sb = SystemBackend()
    host = sb.device("Test Device")
    sb._changes = set()

    host.serve(TLS, HTTP).dns("example.com", "example.org")
    assert len(sb._changes) == 3
    assert host.entity in sb._changes               # DNS names added
    assert host.entity.children[0] in sb._changes   # TLS and HTTP service added
    assert host.entity.children[1] in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 3
    for entry in serialized:
        match entry:
            case {"type": "host"}:
                assert entry["address"] == "Test_Device"
                assert "example.org|name" in entry["addresses"]
                assert "example.com|name" in entry["addresses"]
                assert "Test_Device" in entry["addresses"]

            case {"type": "service", "name": "TLS:443"}:
                assert entry["address"] == "Test_Device/tcp:443"

            case {"type": "service", "name": "HTTP:80"}:
                assert entry["address"] == "Test_Device/tcp:80"

            case _:
                pytest.fail("Unexpected entry in serialized changes")


def test_add_connection():
    sb = SystemBackend()
    dev1 = sb.device("Test Device 1")
    dev2 = sb.device("Test Device 2")
    sb._changes = set()

    con = dev1 >> dev2 / TCP(123)
    assert len(sb._changes) == 2
    assert con.connection in sb._changes            # Connection added
    assert dev2.entity.children[0] in sb._changes   # TCP service added

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 2
    for entry in serialized:
        match entry:
            case {"type": "connection"}:
                assert entry["name"] == "TCP:123"
                assert entry["source_address"] == "Test_Device_1"
                assert entry["target_address"] == "Test_Device_2/tcp:123"
                assert entry["address"] == "source=Test_Device_1&target=Test_Device_2/tcp:123"

            case {"type": "service"}:
                assert entry["name"] == "TCP:123"
                assert entry["address"] == "Test_Device_2/tcp:123"
                assert entry["parent_address"] == "Test_Device_2"

            case _:
                pytest.fail("Unexpected entry in serialized changes")


def test_modify_system_network():
    sb = SystemBackend()
    network = sb.network(ip_mask="10.42.0.0/16").network

    assert len(sb._changes) == 1
    assert network in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "network"
    assert serialized[0]["name"] == "local"
    assert serialized[0]["address"] == "network=10.42.0.0/16"


def test_add_mobile_permissions():
    sb = SystemBackend()
    mobile = sb.mobile("Test Mobile")
    sb._changes = set()

    mobile.set_permissions(NETWORK, LOCATION)
    assert len(sb._changes) == 1
    assert mobile.entity.components[0] in sb._changes # Software modified

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "sw"
    assert NETWORK.value in serialized[0]["permissions"]
    assert LOCATION.value in serialized[0]["permissions"]
    assert serialized[0]["address"] == "Test_Mobile&software=Test_Mobile_SW"
    assert serialized[0]["parent_address"] == "Test_Mobile"


def test_add_arp_to_host():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    arp = dev / ARP
    assert len(sb._changes) == 4
    assert arp.entity in sb._changes                # ARP service added
    assert dev.entity.connections[0] in sb._changes # Connection from device ARP service to broadcast ARP service

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 4

    for entry in serialized:
        match entry:
            case {"type": "host"}:
                assert entry["address"] == "ff_ff_ff_ff_ff_ff"
                assert entry["name"] == "ff:ff:ff:ff:ff:ff"
                assert entry["parent_address"] == ""

            case {"type": "connection"}:
                assert entry["name"] == "ARP"
                assert entry["source_address"] == "Test_Device/arp"
                assert entry["target_address"] == "ff_ff_ff_ff_ff_ff/arp"
                assert entry["address"] == "source=Test_Device/arp&target=ff_ff_ff_ff_ff_ff/arp"

            case {"type": "service", "address": "ff_ff_ff_ff_ff_ff/arp"}:
                assert entry["name"] == "ARP"
                assert entry["parent_address"] == "ff_ff_ff_ff_ff_ff"

            case {"type": "service", "address": "Test_Device/arp"}:
                assert entry["name"] == "ARP"
                assert entry["parent_address"] == "Test_Device"

            case _:
                pytest.fail("Unexpected entry in serialized changes")


def test_add_connection_with_udp_port_range():
    sb = SystemBackend()
    dev1 = sb.device("Test Device 1")
    dev2 = sb.device("Test Device 2")
    sb._changes = set()

    con = dev1 >> dev2 / UDP().port_range(1000, 2000)
    assert len(sb._changes) == 2
    assert con.connection in sb._changes            # Connection added
    assert dev2.entity.children[0] in sb._changes   # UDP service added

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 2
    for entry in serialized:
        match entry:
            case {"type": "connection"}:
                assert entry["name"] == "UDP:1000-2000"
                assert entry["source_address"] == "Test_Device_1"
                assert entry["target_address"] == "Test_Device_2/udp:1000"
                assert entry["address"] == "source=Test_Device_1&target=Test_Device_2/udp:1000"

            case {"type": "service"}:
                assert entry["name"] == "UDP:1000-2000"
                assert entry["address"] == "Test_Device_2/udp:1000"
                assert entry["parent_address"] == "Test_Device_2"
                assert entry["port_range"] =="1000-2000"

            case _:
                pytest.fail("Unexpected entry in serialized changes")


def test_add_udp_broadcast():
    sb = SystemBackend()
    broadcast = sb.any("Broadcast")
    mob = sb.mobile("Test Mobile")
    sb._changes = set()

    con = mob >> broadcast / UDP(port=1234).broadcast()
    assert len(sb._changes) == 2
    assert con.connection in sb._changes
    assert broadcast.entity.children[0] in sb._changes  # Service added

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 2
    for entry in serialized:
        match entry:
            case {"type": "connection"}:
                assert entry["name"] == "UDP:1234 255.255.255.255"
                assert entry["source_address"] == "Test_Mobile"
                assert entry["target_address"] == "Broadcast/udp:1234"
                assert entry["address"] == "source=Test_Mobile&target=Broadcast/udp:1234"

            case {"type": "service"}:
                assert entry["address"] == "Broadcast/udp:1234"
                assert entry["parent_address"] == "Broadcast"
                assert entry["multicast_target"] == "255.255.255.255"

            case _:
                pytest.fail("Unexpected entry in serialized changes")


def test_add_ip_multicast():
    sb = SystemBackend()
    mob = sb.mobile("Test Mobile")
    any_host = sb.any("Any Host")
    sb._changes = set()

    igmp = any_host / IP(protocol=2).multicast("230.0.0.1")
    con = mob >> igmp
    assert len(sb._changes) == 2
    assert igmp.entity in sb._changes
    assert con.connection in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 2
    for entry in serialized:
        match entry:
            case {"type": "connection"}:
                assert entry["name"] == "IP:2 230.0.0.1"
                assert entry["source_address"] == "Test_Mobile"
                assert entry["target_address"] == "Any_Host/ip:2"
                assert entry["address"] == "source=Test_Mobile&target=Any_Host/ip:2"

            case {"type": "service"}:
                assert entry["name"] == "IP:2 230.0.0.1"
                assert entry["address"] == "Any_Host/ip:2"
                assert entry["parent_address"] == "Any_Host"
                assert entry["protocol"] == "" # This IP(protocol=2) is not reflected here, just pointing that out


def test_add_udp_multicast():
    sb = SystemBackend()
    any_host = sb.any("Any Host")
    mob = sb.mobile("Test Mobile")
    sb._changes = set()

    mdns = (any_host / UDP(port=1234).multicast("224.0.0.251")).name("mDNS")
    con = mob >> mdns
    assert len(sb._changes) == 2
    assert mdns.entity in sb._changes
    assert con.connection in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 2
    for entry in serialized:
        match entry:
            case {"type": "connection"}:
                assert entry["name"] == "mDNS"
                assert entry["source_address"] == "Test_Mobile"
                assert entry["target_address"] == "Any_Host/udp:1234"
                assert entry["address"] == "source=Test_Mobile&target=Any_Host/udp:1234"

            case {"type": "service"}:
                assert entry["name"] == "mDNS"
                assert entry["address"] == "Any_Host/udp:1234"
                assert entry["parent_address"] == "Any_Host"
                assert entry["multicast_target"] == "224.0.0.251"


def test_add_sbom():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.software().sbom(["sw1", "sw2"])
    assert len(sb._changes) == 1
    assert dev.entity.components[0] in sb._changes  # Software modified

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "sw"
    assert {
        "key": "sw1",
        "name": "sw1",
        "version": "",
    } in serialized[0]["components"]
    assert {
        "key": "sw2",
        "name": "sw2",
        "version": "",
    } in serialized[0]["components"]
    assert serialized[0]["address"] == "Test_Device&software=Test_Device_SW"
    assert serialized[0]["parent_address"] == "Test_Device"


def test_add_ignore_rules():
    sb = SystemBackend()
    sb._changes = set()
    sb.ignore(file_type="testssl").properties(
        "testssl:cert_expirationStatus <hostCert#1>"
    ).because("Testing")

    assert len(sb._changes) == 1
    assert sb.system in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "system"
    assert serialized[0]["address"] == ""
    assert serialized[0]["ignore_rules"] == {
        "rules": {
            "testssl": [{
                "at": [],
                "explanation": "Testing",
                "properties": ["testssl:cert_expirationStatus <hostCert#1>"],
            }]
        }
    }


def test_add_ignore_name_request():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.ignore_name_requests("example.com", "example.org")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "host"
    assert serialized[0]["address"] == "Test_Device"
    assert "example.com" in serialized[0]["ignore_name_requests"]
    assert "example.org" in serialized[0]["ignore_name_requests"]


def test_add_ip_address():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.ip("10.42.1.1")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "host"
    assert serialized[0]["address"] == "Test_Device"
    assert "10.42.1.1" in serialized[0]["addresses"]


def test_add_hw_address():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.hw("aa:bb:cc:dd:ee:ff")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "host"
    assert serialized[0]["address"] == "Test_Device"
    assert "aa:bb:cc:dd:ee:ff|hw" in serialized[0]["addresses"]


def test_add_properties():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.set_property("test:abc")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes

    serialized = sb.serialize_statement_changes()
    assert len(serialized) == 1
    assert serialized[0]["type"] == "host"
    assert serialized[0]["properties"] == {"test:abc": {"verdict": "Incon"}}


def test_add_online_resource():
    sb = SystemBackend()
    sb.online_resource("privacy-policy", url="example.com", keywords=["privacy", "policy"])
    assert len(sb._changes) == 1
    assert sb.system in sb._changes

    # TODO: Add serialization test when online resource serialization is supported
