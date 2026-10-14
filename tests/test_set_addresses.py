from typing import cast

import pytest

from toolsaf.builder_backend import SystemBackend, HostBackend
from toolsaf.common.address import AddressAtNetwork, DNSName, IPAddress
from toolsaf.core.serializer.model_serializer import SystemSerializer
from toolsaf.main import ConfigurationException
from tests.serializers.test_edit_deserialized import _loaded
from tests.test_model import Setup


def _changes(sb: SystemBackend) -> list:
    return [(e["type"], e["address"]) for e in sb.serialize_statement_changes()]


def test_set_addresses():
    sb = _loaded()
    device = sb.hosts_by_name["Device 1"]
    default = sb.system.get_default_network()
    sb._changes = {}

    device.set_addresses(["10.0.0.6", "device.example.com|name", "Device_1"])
    assert device.entity.addresses == {
        device.entity.get_tag(), IPAddress.new("10.0.0.6"), DNSName("device.example.com")}
    assert AddressAtNetwork(IPAddress.new("10.0.0.5"), default) not in sb.entity_by_address
    assert sb.entity_by_address[AddressAtNetwork(IPAddress.new("10.0.0.6"), default)] is device
    assert sb.entity_by_address[AddressAtNetwork(DNSName("device.example.com"), default)] is device
    assert _changes(sb) == [("host", "Device_1")]

    device.set_addresses([])  # only tag remains
    assert device.entity.addresses == {device.entity.get_tag()}
    assert all(b is not device for b in sb.entity_by_address.values())
    assert device.entity.get_system_address().get_parseable_value() == "Device_1"
    assert _changes(sb) == [("host", "Device_1")]


def test_set_addresses_hw():
    sb = _loaded()
    device = sb.hosts_by_name["Device 1"]
    device.set_addresses(["10.0.0.5", "02:00:00:00:00:01|hw"])
    assert {f"{a}" for a in device.entity.addresses} == {"Device_1", "10.0.0.5", "02:00:00:00:00:01"}


def test_set_addresses_errors():
    sb = _loaded()
    device = sb.hosts_by_name["Device 1"]
    before = set(device.entity.addresses)
    sb._changes = {}
    with pytest.raises(ConfigurationException, match="Cannot change tag of Device 1 to Other"):
        device.set_addresses(["Other"])
    with pytest.raises(ConfigurationException, match="Duplicate address cloud.com, reserved by: Cloud"):
        device.set_addresses(["cloud.com|name"])
    with pytest.raises(ConfigurationException, match="Bad address 'x|bad'"):
        device.set_addresses(["x|bad"])
    assert device.entity.addresses == before
    assert _changes(sb) == []


def test_set_addresses_without_tag():
    # host without tag must keep the address it is identified by
    setup = Setup()
    setup.system.system.get_endpoint(IPAddress.new("192.168.4.4"))
    s = SystemSerializer()
    s.deserialize_list(s.serialize(setup.system.system))
    sb = SystemBackend.from_entity(s.model_map[""])
    host = cast(HostBackend, sb.get_backend("192.168.4.4"))
    with pytest.raises(ConfigurationException, match="Addresses change system address of 192.168.4.4"):
        host.set_addresses([])
    with pytest.raises(ConfigurationException, match="Addresses change system address of 192.168.4.4"):
        host.set_addresses(["192.168.4.4", "host.example.com|name"])  # DNS name would take priority
    host.set_addresses(["192.168.4.4"])
