from toolsaf.builder_backend import SystemBackend
from toolsaf.main import TLS, HTTP, TCP, ARP, IP, UDP
from toolsaf.common.android import LOCATION, NETWORK


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


def test_add_host_with_serve_and_dns():
    sb = SystemBackend()
    host = sb.device("Test Device")
    sb._changes = set()

    host.serve(TLS, HTTP).dns("example.com", "example.org")
    assert len(sb._changes) == 3
    assert host.entity in sb._changes               # DNS names added
    assert host.entity.children[0] in sb._changes   # TLS and HTTP service added
    assert host.entity.children[1] in sb._changes


def test_add_connection():
    sb = SystemBackend()
    dev1 = sb.device("Test Device 1")
    dev2 = sb.device("Test Device 2")
    sb._changes = set()

    con = dev1 >> dev2 / TCP(123)
    assert len(sb._changes) == 2
    assert con.connection in sb._changes            # Connection added
    assert dev2.entity.children[0] in sb._changes   # TCP service added


def test_modify_system_network():
    sb = SystemBackend()
    network = sb.network("10.42.0.0/16").network

    assert len(sb._changes) == 1
    assert network in sb._changes


def test_add_mobile_permissions():
    sb = SystemBackend()
    mobile = sb.mobile("Test Mobile")
    sb._changes = set()

    mobile.set_permissions(NETWORK, LOCATION)
    assert len(sb._changes) == 1
    assert mobile.entity.components[0] in sb._changes # Software modified


def test_add_arp_to_host():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    arp = dev / ARP
    assert len(sb._changes) == 4
    assert arp.entity in sb._changes                # ARP service added
    assert dev.entity.connections[0] in sb._changes # Connection from device ARP service to broadcast ARP service
    sb._changes.remove(arp.entity)
    sb._changes.remove(dev.entity.connections[0])

    rest_of_changes = {"ff_ff_ff_ff_ff_ff", "ff_ff_ff_ff_ff_ff/arp"}
    for entry in sb._changes:
        sys_addr = entry.get_system_address().get_parseable_value()
        assert sys_addr in rest_of_changes          # Broadcast ARP stuff
        rest_of_changes.remove(sys_addr)


def test_add_connection_with_udp_port_range():
    sb = SystemBackend()
    dev1 = sb.device("Test Device 1")
    dev2 = sb.device("Test Device 2")
    sb._changes = set()

    con = dev1 >> dev2 / UDP().port_range(1000, 2000)
    assert len(sb._changes) == 2
    assert con.connection in sb._changes            # Connection added
    assert dev2.entity.children[0] in sb._changes   # UDP service added


def test_add_udp_broadcast():
    sb = SystemBackend()
    broadcast = sb.any("Broadcast")
    mob = sb.mobile("Test Mobile")
    sb._changes = set()

    con = mob >> broadcast / UDP(port=1234).broadcast()
    assert len(sb._changes) == 2
    assert con.connection in sb._changes
    assert broadcast.entity.children[0] in sb._changes  # Service added


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


def test_add_sbom():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.software().sbom(["sw1", "sw2"])
    assert len(sb._changes) == 1
    assert dev.entity.components[0] in sb._changes  # Software modified


def test_add_ignore_rules():
    sb = SystemBackend()
    sb.ignore(file_type="testssl").properties(
        "testssl:cert_expirationStatus <hostCert#1>"
    ).because("Testing")

    assert len(sb._changes) == 1
    assert sb.system in sb._changes


def test_add_ignore_name_request():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.ignore_name_requests("example.com")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes


def test_add_ip_address():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.ip("10.42.1.1")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes


def test_add_hw_address():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.hw("aa:bb:cc:dd:ee:ff")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes


def test_add_properties():
    sb = SystemBackend()
    dev = sb.device("Test Device")
    sb._changes = set()

    dev.set_property("test:abc")
    assert len(sb._changes) == 1
    assert dev.entity in sb._changes


def test_add_online_resource():
    sb = SystemBackend()
    sb.online_resource("privacy-policy", url="example.com", keywords=["privacy", "policy"])
    assert len(sb._changes) == 1
    assert sb.system in sb._changes
