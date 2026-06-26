from typing import cast
from tests.test_model import Setup
from toolsaf.main import TLS, HTTP, DHCP, DNS, UDP, NTP, MQTT, TCP
from toolsaf.common.address import Protocol, IPAddress, AddressAtNetwork, DNSName
from toolsaf.core.serializer.model_serializer import SystemSerializer
from toolsaf.core.address_ranges import NULL_PORT_RANGE, PortRange
from toolsaf.core.model import Service, Connection
from toolsaf.builder_backend import SystemBackend, HostBackend, ServiceBackend, SoftwareBackend, ConnectionBackend


def _loaded():
    system = Setup().system
    system.network(ip_mask="10.0.0.0/16")
    dev = system.device("Device 1").serve(HTTP, TLS).ip("10.0.0.5")
    dev / DHCP / DNS
    dev.software("FW").sbom(["libc"])

    cloud = system.device("Cloud").serve(HTTP).dns("cloud.com")
    dev >> cloud / HTTP

    any_host = system.any("Services")
    mdns = any_host / UDP(port=5353, administrative=True).multicast("224.1.1.1")
    mdns.name("mDNS")
    dev >> mdns
    cloud >> any_host / UDP().ports(7001, 7002).broadcast()

    system.ignore(file_type="testssl").properties("testssl:BREACH").at(dev / TLS).because("Testing")

    s = SystemSerializer()
    s.deserialize_list(s.serialize(system.system))
    return SystemBackend.from_entity(s.model_map[""])


def test_cache_population():
    sb = _loaded()

    # There should be no changes right after loading
    assert len(sb._changes) == 0
    # 1 system, 3 hosts, 7 services, 1 software, 3 connections
    assert len(sb.backends_by_entity) == 15

    assert "Device 1" in sb.hosts_by_name and sb.hosts_by_name["Device 1"] is not None
    assert ("", NULL_PORT_RANGE, Protocol.TCP, 80) in sb.hosts_by_name["Device 1"].service_builders
    assert ("", NULL_PORT_RANGE, Protocol.TCP, 443) in sb.hosts_by_name["Device 1"].service_builders
    assert ("", NULL_PORT_RANGE, Protocol.UDP, 53) in sb.hosts_by_name["Device 1"].service_builders
    assert ("", NULL_PORT_RANGE, Protocol.UDP, 67) in sb.hosts_by_name["Device 1"].service_builders
    assert (AddressAtNetwork(IPAddress.new("10.0.0.5"), sb.system.get_default_network())) in sb.entity_by_address
    assert "FW" in sb.hosts_by_name["Device 1"].sw and sb.hosts_by_name["Device 1"].sw["FW"] is not None
    assert len(sb.hosts_by_name["Device 1"].sw) == 1

    assert "Cloud" in sb.hosts_by_name and sb.hosts_by_name["Cloud"] is not None
    assert ("", NULL_PORT_RANGE, Protocol.TCP, 80) in sb.hosts_by_name["Cloud"].service_builders
    assert (AddressAtNetwork(DNSName("cloud.com"), sb.system.get_default_network())) in sb.entity_by_address
    assert len(sb.hosts_by_name["Cloud"].sw) == 0

    assert "Services" in sb.hosts_by_name and sb.hosts_by_name["Services"] is not None
    assert ("224.1.1.1", NULL_PORT_RANGE, Protocol.UDP, 5353) in sb.hosts_by_name["Services"].service_builders
    assert ("255.255.255.255", PortRange([(7001, 7001)])+PortRange([(7002, 7002)]), Protocol.UDP, -1) in sb.hosts_by_name["Services"].service_builders
    assert len(sb.hosts_by_name["Services"].sw) == 0

    assert len(sb.entity_by_address) == 2

    assert "testssl" in sb.ignore_backend.ignore_rules.rules and sb.ignore_backend.ignore_rules.rules["testssl"] is not None


def test_getting_by_system_address():
    sb = _loaded()
    # Device
    assert isinstance(sb.get_backend("Device_1"), HostBackend)
    assert isinstance(sb.get_backend("Device_1/tcp:80"), ServiceBackend)        # HTTP
    assert isinstance(sb.get_backend("Device_1/tcp:443"), ServiceBackend)       # TLS
    assert isinstance(sb.get_backend("Device_1/udp:53"), ServiceBackend)        # DNS
    assert isinstance(sb.get_backend("Device_1/udp:67"), ServiceBackend)        # DHCP
    assert isinstance(sb.get_backend("Device_1&software=FW"), SoftwareBackend)
    # Cloud
    assert isinstance(sb.get_backend("Cloud"), HostBackend)
    assert isinstance(sb.get_backend("Cloud/tcp:80"), ServiceBackend)
    # Services by the environment
    assert isinstance(sb.get_backend("Services"), HostBackend)
    assert isinstance(sb.get_backend("Services/udp:5353"), ServiceBackend)      # mDNS
    assert isinstance(sb.get_backend("Services/udp:7001"), ServiceBackend)      # Broadcast 7001-7002
    # Connections
    assert isinstance(sb.get_backend("source=Device_1&target=Cloud/tcp:80"), ConnectionBackend)
    assert isinstance(sb.get_backend("source=Device_1&target=Services/udp:5353"), ConnectionBackend)
    assert isinstance(sb.get_backend("source=Cloud&target=Services/udp:7001"), ConnectionBackend)

    assert sb.get_backend("Nonexistent") is None


def test_duplication_protection():
    sb = _loaded()
    iot_system = sb.system

    assert len(iot_system.children) == 3
    assert len(sb.hosts_by_name["Device 1"].entity.children) == 4
    assert len(sb.hosts_by_name["Device 1"].sw) == 1
    assert len(sb.hosts_by_name["Device 1"].entity.connections) == 2
    assert len(sb.hosts_by_name["Cloud"].entity.children) == 1
    assert len(sb.hosts_by_name["Cloud"].entity.connections) == 2
    assert len(sb.hosts_by_name["Services"].entity.children) == 2
    assert len(sb.hosts_by_name["Services"].entity.connections) == 2

    sb.device("Device 1").serve(HTTP, TLS) / DHCP / DNS
    sb.device("Device 1").software("FW")
    sb.backend("Cloud").serve(HTTP)
    sb.any("Services")
    sb.device("Device 1") >> sb.backend("Cloud") / HTTP
    sb.backend("Cloud") >> sb.any("Services") / UDP().ports(7001, 7002).broadcast()

    assert len(iot_system.children) == 3
    assert len(sb.hosts_by_name["Device 1"].entity.children) == 4
    assert len(sb.hosts_by_name["Device 1"].sw) == 1
    assert len(sb.hosts_by_name["Device 1"].entity.connections) == 2
    assert len(sb.hosts_by_name["Cloud"].entity.children) == 1
    assert len(sb.hosts_by_name["Cloud"].entity.connections) == 2
    assert len(sb.hosts_by_name["Services"].entity.children) == 2
    assert len(sb.hosts_by_name["Services"].entity.connections) == 2


def test_getter_rename_safety():
    sb = _loaded()
    b = cast(HostBackend, sb.get_backend("Device_1"))
    for address in b.entity.addresses:
        if address.is_tag():
            address.tag = "Device_1_Renamed"
    assert sb.get_backend("Device_1") is None
    assert sb.get_backend("Device_1_Renamed") is b


def test_dhcp_source_fixer_reattached():
    system = Setup().system
    system.device("Device 1") / DHCP / NTP
    s = SystemSerializer()
    s.deserialize_list(s.serialize(system.system))
    sb = SystemBackend.from_entity(s.model_map[""])

    dhcp = cast(ServiceBackend, sb.get_backend("Device_1/udp:67"))
    assert dhcp.source_fixer is not None

    ntp = cast(ServiceBackend, sb.get_backend("Device_1/udp:123"))
    assert ntp.source_fixer is None


def test_edit_deserialized_and_serialize():
    sb = _loaded()
    dev = cast(HostBackend, sb.get_backend("Device_1"))
    cloud = cast(HostBackend, sb.get_backend("Cloud"))
    assert len(sb._changes) == 0

    dev.set_property("edited", "ok")
    assert len(sb._changes) == 1
    assert sb._changes.pop() is dev.entity

    cloud.serve(MQTT)
    assert len(sb._changes) == 1
    assert isinstance(sb._changes.pop(), Service)

    cloud >> dev / TCP(port=8888)
    assert len(sb._changes) == 2
    expected_types = {Service, Connection}
    for entry in sb._changes:
        assert type(entry) in expected_types
        expected_types.remove(type(entry))
    sb._changes.clear()

    entities = SystemSerializer().serialize(sb.system)
    assert len(entities) == 19
