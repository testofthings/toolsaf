from typing import cast

import pytest

from toolsaf.builder_backend import SystemBackend, ServiceBackend
from toolsaf.common.address import Addresses, IPAddress
from toolsaf.common.entity import Entity
from toolsaf.common.basics import Status
from toolsaf.common.property import PropertyKey
from toolsaf.common.traffic import Evidence, EvidenceSource
from toolsaf.common.verdict import Verdict
from toolsaf.core.event_interface import PropertyEvent
from toolsaf.core.serializer.event_serializer import EventSerializer
from toolsaf.core.serializer.model_serializer import SystemSerializer
from toolsaf.main import ConfigurationException, TLS
from tests.serializers.test_edit_deserialized import _loaded
from tests.test_model import Setup


def _reload(sb: SystemBackend) -> SystemBackend:
    """Serialize and deserialize, check system addresses"""
    s = SystemSerializer()
    s.deserialize_list(s.serialize(sb.system))
    sb.system.check_unique_system_addresses()
    return SystemBackend.from_entity(s.model_map[""])


def _changes(sb: SystemBackend) -> list:
    return [(e["type"], e["address"]) for e in sb.serialize_statement_changes()]


def _entity(sb: SystemBackend, address: str) -> Entity:
    """Find entity by system address"""
    entity = sb.system.find_entity(Addresses.parse_system_address(address))
    assert entity is not None, address
    return entity


def test_remove_connection():
    sb = _loaded()
    c = _entity(sb, "source=Device_1&target=Cloud/tcp:80")
    sb.remove_entity(c)
    assert _changes(sb) == [("removed", "source=Device_1&target=Cloud/tcp:80")]
    assert c not in sb.hosts_by_name["Device 1"].entity.connections
    assert c not in sb.hosts_by_name["Cloud"].entity.connections
    assert sb.get_backend("source=Device_1&target=Cloud/tcp:80") is None
    assert _reload(sb).get_backend("source=Device_1&target=Cloud/tcp:80") is None


def test_remove_connection_used_for_updates():
    sb = _loaded()
    sb.device("Device 1").software("FW").updates_from(sb.backend("Cloud"))
    sb._changes = {}
    with pytest.raises(ConfigurationException, match="used for updates by FW"):
        sb.remove_entity(_entity(sb, "source=Device_1&target=Cloud/tcp:80"))
    assert _changes(sb) == []


def test_remove_service_with_connection():
    sb = _loaded()
    with pytest.raises(ConfigurationException,
                       match="Remove first connections of Cloud HTTP:80: Device 1 => Cloud HTTP:80"):
        sb.remove_entity(_entity(sb, "Cloud/tcp:80"))
    assert _changes(sb) == []
    assert sb.get_backend("Cloud/tcp:80") is not None


def test_remove_service_with_ignore_rule():
    sb = _loaded()
    assert "testssl" in sb.system.ignore_rules.rules  # at Device_1/tcp:443
    tls = cast(ServiceBackend, sb.get_backend("Device_1/tcp:443"))
    sb.remove_entity(tls.entity)
    assert "testssl" not in sb.system.ignore_rules.rules
    assert _changes(sb) == [("removed", "Device_1/tcp:443"), ("system", "")]
    assert tls.entity not in sb.hosts_by_name["Device 1"].entity.children
    assert all(b is not tls for b in sb.hosts_by_name["Device 1"].service_builders.values())

    # service can be created again, with the same address
    new_tls = sb.device("Device 1") / TLS
    assert new_tls is not tls
    assert new_tls.entity.get_system_address().get_parseable_value() == "Device_1/tcp:443"
    assert "testssl" not in _reload(sb).system.ignore_rules.rules


def test_ignore_rule_with_many_locations():
    sb = _loaded()
    rule = sb.system.ignore_rules.rules["testssl"][0]
    rule.at.add("Device_1/tcp:80")
    sb.remove_entity(_entity(sb, "Device_1/tcp:443"))
    assert rule.at == {"Device_1/tcp:80"}  # rule remains for the other location
    assert sb.system.ignore_rules.rules["testssl"] == [rule]


def test_remove_host():
    sb = _loaded()
    device = sb.hosts_by_name["Device 1"]
    with pytest.raises(ConfigurationException, match="Remove first connections of Device 1: "):
        sb.remove_entity(device.entity)
    for address in ["source=Device_1&target=Cloud/tcp:80", "source=Device_1&target=Services/udp:5353"]:
        sb.remove_entity(_entity(sb, address))
    dns = sb.get_backend("Device_1/udp:53")
    assert isinstance(dns, ServiceBackend) and dns.entity in sb.system.message_listeners
    sb.remove_entity(_entity(sb, "Device_1"))

    # dependents before the ones they depend on
    assert _changes(sb) == [
        ("removed", "source=Device_1&target=Cloud/tcp:80"),
        ("removed", "source=Device_1&target=Services/udp:5353"),
        ("removed", "Device_1&software=FW"),
        ("removed", "Device_1/tcp:443"),
        ("removed", "Device_1/tcp:80"),
        ("removed", "Device_1/udp:53"),
        ("removed", "Device_1/udp:67"),
        ("removed", "Device_1"),
        ("system", ""),  # ignore rule removed
    ]
    assert device.entity not in sb.system.children
    assert "Device 1" not in sb.hosts_by_name
    assert all(b is not device for b in sb.entity_by_address.values())
    assert dns.entity not in sb.system.message_listeners
    assert all(e.get_system_address().get_parseable_value()[:8] != "Device_1" for e in sb.backends_by_entity)
    sb.finish_()
    assert len(_reload(sb).system.get_hosts()) == 2


def test_remove_and_create_host_again():
    sb = _loaded()
    host = sb.backend("Lonely")
    sb.serialize_statement_changes()
    sb.remove_entity(host.entity)
    sb.backend("Lonely")  # same system address
    assert _changes(sb) == [("removed", "Lonely"), ("host", "Lonely")]


def test_remove_software_and_cookies():
    sb = _loaded()
    sw = _entity(sb, "Device_1&software=FW")
    sb.remove_entity(sw)
    assert _changes(sb) == [("removed", "Device_1&software=FW")]
    assert sw not in sb.hosts_by_name["Device 1"].entity.components
    assert sb.hosts_by_name["Device 1"].sw == {}

    browser = sb.browser("Browser")
    cookies = browser.cookies().set({"session": ("example.com", "/", "Session")})
    sb.serialize_statement_changes()
    sb.remove_entity(_entity(sb, "Browser&cookies=Cookies"))
    assert _changes(sb) == [("removed", "Browser&cookies=Cookies")]
    assert cookies.component not in browser.entity.components


def test_remove_unexpected_host():
    setup = Setup()
    setup.system.system.get_endpoint(IPAddress.new("192.168.4.4"))
    sb = _reload(setup.system)
    host = _entity(sb, "192.168.4.4")
    assert host.status == Status.UNEXPECTED
    sb.remove_entity(host)
    assert _changes(sb) == [("removed", "192.168.4.4")]


def test_remove_network():
    sb = SystemBackend()
    vpn = sb.network("VPN", ip_mask="10.10.0.0/16")
    sb.device("Device").in_networks(vpn)
    with pytest.raises(ConfigurationException, match="Network VPN is used by Device"):
        sb.remove_network(vpn.network)
    with pytest.raises(ConfigurationException, match="Cannot remove system network default"):
        sb.remove_network(sb.system.get_default_network())

    unused = sb.network("Unused", ip_mask="10.20.0.0/16")
    sb.serialize_statement_changes()
    sb.remove_network(unused.network)
    assert _changes(sb) == [("removed", "network=Unused")]


def test_skip_event_of_removed_entity():
    setup = Setup()
    software = setup.system.device("Device").software("FW").sw
    source = EvidenceSource(name="Test", base_ref="test.json")
    event = PropertyEvent(Evidence(source), software, PropertyKey("check").verdict(Verdict.PASS))
    records = EventSerializer(setup.get_system()).serialize(event)

    setup.system.remove_entity(software)
    serializer = EventSerializer(setup.get_system())
    assert [serializer.deserialize(r) for r in records][-1] is None


def test_remove_system():
    sb = _loaded()
    with pytest.raises(ConfigurationException, match="Cannot remove the system"):
        sb.remove_entity(sb.system)
