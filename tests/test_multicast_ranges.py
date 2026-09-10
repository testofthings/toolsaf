"""Test multicast and its address range handling"""

import pytest

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
    assert parsed.fixed_addresses == [IPAddress.new("255.255.255.255")]
    assert parsed.address_range is None

    # what if fixed address
    mc = MulticastTarget(fixed_addresses=[IPAddress.new("255.255.255.255")])
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

    mc = MulticastTarget(address_range=AddressRange.parse_range("100-110.255.255.255"))
    assert not mc.is_match(IPAddress.new("99.255.255.255"))
    assert mc.is_match(IPAddress.new("100.255.255.255"))
    assert mc.is_match(IPAddress.new("105.255.255.255"))
    assert not mc.is_match(IPAddress.new("105.255.255.254"))
    assert mc.is_match(IPAddress.new("110.255.255.255"))
    assert not mc.is_match(IPAddress.new("111.255.255.255"))
    assert not mc.is_match(IPAddress.new("255.255.255.255"))


def test_multicast_ipv6_fixed_address():
    mc = MulticastTarget(fixed_addresses=[IPAddress.new("ff02::1")])
    assert mc.is_match(IPAddress.new("ff02::1"))
    assert not mc.is_match(IPAddress.new("ff02::2"))

    assert mc.get_parseable_value() == "ff02::1"
    parsed = MulticastTarget.parse_address_range(mc.get_parseable_value())
    assert parsed == mc


def test_multicast_target_multiple_fixed_addresses():
    mc = MulticastTarget.from_specs(["255.255.255.255", "ff02::1", "ff02::2"])
    assert mc.is_match(IPAddress.new("255.255.255.255"))
    assert mc.is_match(IPAddress.new("ff02::1"))
    assert mc.is_match(IPAddress.new("ff02::2"))
    assert not mc.is_match(IPAddress.new("ff02::16"))

    assert mc.get_parseable_value() == "255.255.255.255,ff02::1,ff02::2"
    parsed = MulticastTarget.parse_address_range(mc.get_parseable_value())
    assert parsed == mc

    # a single spec still parses into one fixed address, not a one-item comma list quirk
    single = MulticastTarget.from_specs(["ff02::1"])
    assert single.fixed_addresses == [IPAddress.new("ff02::1")]

    # a wildcard range is only recognized when given as the sole spec
    ranged = MulticastTarget.from_specs(["*.*.255.255"])
    assert ranged.address_range is not None
    assert ranged.is_match(IPAddress.new("1.2.255.255"))


def test_multicast_parsing_errors():
    with pytest.raises(ValueError, match="Expected 4-part address, got '255.255.255'"):
        AddressRange.parse_range("255.255.255")

    with pytest.raises(ValueError, match="Non-integer in segment 'x' in '255.x.255.255'"):
        AddressRange.parse_range("255.x.255.255")

    with pytest.raises(ValueError, match="Invalid segment '5-1' in '255.5-1.255.255'"):
        AddressRange.parse_range("255.5-1.255.255")

    with pytest.raises(ValueError, match="Invalid segment '1-300' in '255.1-300.255.255'"):
        AddressRange.parse_range("255.1-300.255.255")
