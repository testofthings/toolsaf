import ipaddress
from typing import cast

import pytest
from tests.test_model import Setup
from toolsaf.main import TLS, HTTP, DHCP, DNS, UDP, NTP, MQTT, TCP, SSH, ConfigurationException
from toolsaf.common.address import Protocol, IPAddress, AddressAtNetwork, DNSName
from toolsaf.common.basics import Status
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

    dev.ip("1.2.3.4")
    assert len(sb._changes) == 1
    assert sb._changes.popitem()[0] is dev.entity

    cloud.serve(MQTT)
    assert len(sb._changes) == 1
    assert isinstance(sb._changes.popitem()[0], Service)

    cloud >> dev / TCP(port=8888)
    assert len(sb._changes) == 2
    expected_types = {Service, Connection}
    for entry in sb._changes:
        assert type(entry) in expected_types
        expected_types.remove(type(entry))
    sb._changes.clear()

    entities = SystemSerializer().serialize(sb.system)
    assert len(entities) == 19


def test_networks_of_loaded_statement():
    system = Setup().system
    local = system.network(ip_mask="10.0.0.0/16")
    loopback = system.network(ip_mask="127.0.0.0/8")
    dev = system.device("Device 1").in_networks(local, loopback)
    dev / SSH().in_network(loopback)
    dev.ip("10.0.0.5")

    s = SystemSerializer()
    s.deserialize_list(s.serialize(system.system))
    sb = SystemBackend.from_entity(s.model_map[""])

    # Only the local network belongs to the system itself
    assert sb.system.networks == [local.network]
    assert sb.system.get_default_network().ip_network == ipaddress.ip_network("10.0.0.0/16")

    host = cast(HostBackend, sb.get_backend("Device_1"))
    assert [n.name for n in host.entity.networks] == ["default", "loopback"]
    assert host.entity.networks[0].ip_network == ipaddress.ip_network("10.0.0.0/16")
    assert host.entity.networks[1].ip_network == ipaddress.ip_network("127.0.0.0/8")

    ssh = cast(ServiceBackend, sb.get_backend("Device_1/tcp:22"))
    assert [n.name for n in ssh.entity.networks] == ["loopback"]
    # The same network object is shared by all entities using it
    assert ssh.entity.networks[0] is host.entity.networks[1]

    # Host addresses are registered at the networks they belong to
    assert AddressAtNetwork(IPAddress.new("10.0.0.5"), host.entity.networks[0]) in sb.entity_by_address
    assert AddressAtNetwork(IPAddress.new("10.0.0.5"), host.entity.networks[1]) not in sb.entity_by_address
    assert len(sb._changes) == 0


def _system_addresses(sb: SystemBackend) -> dict:
    return {e: e.get_system_address().get_parseable_value() for e in sb.backends_by_entity}


def test_name_change():
    sb = _loaded()
    addresses = _system_addresses(sb)
    device = cast(HostBackend, sb.get_backend("Device_1"))
    web = cast(ServiceBackend, sb.get_backend("Device_1/tcp:80"))
    fw = cast(SoftwareBackend, sb.get_backend("Device_1&software=FW"))
    cloud = cast(HostBackend, sb.get_backend("Cloud"))

    device.name("Lamp")
    web.name("Web UI")
    fw.name("Firmware")
    cloud.name("cloud.example.org", check_dns=False)  # looks like DNS name, but it is just a name

    assert (device.entity.name, web.entity.name, fw.sw.name, cloud.entity.name) == \
        ("Lamp", "Web UI", "Firmware", "cloud.example.org")
    assert DNSName("cloud.example.org") not in cloud.entity.addresses
    # No system address changes, incl. connections
    assert _system_addresses(sb) == addresses
    assert sb.get_backend("Device_1") is device
    assert sb.get_backend("Device_1/tcp:80") is web
    assert sb.get_backend("Device_1&software=FW") is fw
    assert sb.get_backend("Cloud") is cloud

    # Only renamed entities are changed
    assert sb._changes.keys() == {device.entity, web.entity, fw.sw, cloud.entity}
    changes = sb.serialize_statement_changes()
    assert {(e["name"], e["address"]) for e in changes} == {
        ("Lamp", "Device_1"), ("Web UI", "Device_1/tcp:80"),
        ("Firmware", "Device_1&software=FW"), ("cloud.example.org", "Cloud")}

    # Builder finds the renamed entities by the new names
    assert sb.device("Lamp") is device
    assert sb.device("Lamp").software("Firmware") is fw
    assert sb.backend("cloud.example.org") is cloud
    assert "Device 1" not in sb.hosts_by_name
    with pytest.raises(ConfigurationException, match="conflicts with system address 'Device_1' of host 'Lamp'"):
        sb.device("Device 1")
    sb.finish_()

    # Names and addresses survive serialization
    s = SystemSerializer()
    s.deserialize_list(s.serialize(sb.system))
    reloaded = SystemBackend.from_entity(s.model_map[""])
    reloaded_names = {e.get_system_address().get_parseable_value(): getattr(e, "name", None)
                      for e in reloaded.backends_by_entity}
    for entity, address in addresses.items():  # finish_ added default software for Cloud, ignore it
        assert reloaded_names[address] == getattr(entity, "name", None)
    assert reloaded.get_backend("Device_1&software=FW") is reloaded.device("Lamp").software("Firmware")


def test_name_change_conflicts():
    sb = _loaded()
    device = cast(HostBackend, sb.get_backend("Device_1"))
    sb._changes = {}

    with pytest.raises(ConfigurationException, match="Name Cloud already used"):
        device.name("Cloud")
    with pytest.raises(ConfigurationException, match="Name TLS:443 already used"):
        cast(ServiceBackend, sb.get_backend("Device_1/tcp:80")).name("TLS:443")
    with pytest.raises(ConfigurationException, match="Name cannot be empty"):
        device.name("")
    device.software("Other")
    sb._changes = {}
    with pytest.raises(ConfigurationException, match="Software Other already defined"):
        cast(SoftwareBackend, sb.get_backend("Device_1&software=FW")).name("Other")

    # Same name for services of different hosts is fine
    cast(ServiceBackend, sb.get_backend("Cloud/tcp:80")).name("Web")
    cast(ServiceBackend, sb.get_backend("Device_1/tcp:80")).name("Web")
    # Renaming to the current name does nothing
    assert device.name("Device 1") is device
    assert {e.name for e in sb._changes} == {"Web"}
    assert device.entity.name == "Device 1"


def test_name_change_unexpected_host():
    setup = Setup()
    setup.system.system.get_endpoint(IPAddress.new("192.168.4.4"))  # unexpected host, no tag
    s = SystemSerializer()
    s.deserialize_list(s.serialize(setup.system.system))
    sb = SystemBackend.from_entity(s.model_map[""])

    host = cast(HostBackend, sb.get_backend("192.168.4.4"))
    assert host.entity.status == Status.UNEXPECTED
    host.name("Mystery host")
    assert host.entity.name == "Mystery host"
    assert host.entity.get_system_address().get_parseable_value() == "192.168.4.4"


def test_name_change_dns():
    sb = _loaded()
    device = cast(HostBackend, sb.get_backend("Device_1"))
    sb._changes = {}

    # Not a valid DNS name, fails before changing anything
    with pytest.raises(ValueError, match="Invalid DNS label"):
        device.name("Hub v2.1")
    assert device.entity.name == "Device 1"
    assert not sb._changes

    device.name("Hub v2.1", check_dns=False)
    assert device.entity.name == "Hub v2.1"
    assert not any(isinstance(a, DNSName) for a in device.entity.addresses)

    device.name("hub.example.com")
    assert device.entity.name == "hub.example.com"
    assert DNSName("hub.example.com") in device.entity.addresses
    assert device.entity.get_system_address().get_parseable_value() == "Device_1"
