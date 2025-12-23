"""Test multicast and its address range handling"""

from toolsaf.common.address import IPAddress
from toolsaf.core.address_ranges import AddressRange, MulticastTarget


def test_simple_range():
    r = AddressRange.parse_range("255.255.255.255")
    assert r.is_match(IPAddress.new("255.255.255.255"))
    assert not r.is_match(IPAddress.new("255.255.255.254"))

    r = AddressRange.parse_range("*.*.255.255")
    assert r.is_match(IPAddress.new("255.255.255.255"))
    assert not r.is_match(IPAddress.new("255.255.255.254"))
    assert r.is_match(IPAddress.new("2.255.255.255"))
    assert not r.is_match(IPAddress.new("2.255.255.254"))


def test_multicast_range():
    mc = MulticastTarget(address_range=AddressRange.parse_range("255.255.255.255"))
    assert mc.is_match(IPAddress.new("255.255.255.255"))
    assert not mc.is_match(IPAddress.new("255.255.255.254"))

    assert mc.get_parseable_value() == "255.255.255.255"
    parsed = MulticastTarget.parse_address_range(mc.get_parseable_value())
    # this parses into fixed address
    assert parsed.fixed_address == IPAddress.new("255.255.255.255")
    assert parsed.address_range is None

    # what if fixed address
    mc = MulticastTarget(fixed_address=IPAddress.new("255.255.255.255"))
    assert mc.is_match(IPAddress.new("255.255.255.255"))
    assert not mc.is_match(IPAddress.new("255.255.255.254"))

    assert mc.get_parseable_value() == "255.255.255.255"
    parsed = MulticastTarget.parse_address_range(mc.get_parseable_value())
    assert parsed == mc

    mc = MulticastTarget(address_range=AddressRange.parse_range("*.*.255.255"))
    assert mc.is_match(IPAddress.new("255.255.255.255"))
    assert not mc.is_match(IPAddress.new("255.255.255.254"))
    assert mc.is_match(IPAddress.new("2.255.255.255"))
    assert not mc.is_match(IPAddress.new("2.255.255.254"))

    assert mc.get_parseable_value() == "*.*.255.255"
    parsed = MulticastTarget.parse_address_range(mc.get_parseable_value())
    assert parsed == mc


