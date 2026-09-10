"""Test IPv6 matching"""

from toolsaf.builder_backend import SystemBackend
from toolsaf.common.address import EndpointAddress, IPAddress
from toolsaf.common.basics import Status
from toolsaf.common.traffic import IPFlow
from toolsaf.core.matcher import SystemMatcher
from toolsaf.core.matcher_engine import FlowMatcher, MatcherEngine
from toolsaf.main import TCP


def test_hw_address_match():
    sb = SystemBackend()
    engine = MatcherEngine(sb.system)

    dev0 = sb.device("Dev0").hw("a:0:0:0:0:1")

    m = SystemMatcher(sb.system)
    flow = IPFlow.TCP("a:0:0:0:0:1", "192.168.0.1", 20123) >> ("a:0:0:0:0:2", "12.0.0.2", 1234)
    con = m.connection(flow)
    assert con.source == dev0.entity


def test_ipv6_source_match():
    sb = SystemBackend()
    dev0 = sb.device().ip("2001:db8::1")

    m = SystemMatcher(sb.system)
    flow = IPFlow.TCP("1:0:0:0:0:1", "2001:db8::1", 20123) >> ("1:0:0:0:0:2", "2001:db8::2", 1234)
    con = m.connection(flow)
    assert con.source == dev0.entity
    assert con.target.status == Status.UNEXPECTED


def test_ipv6_link_local_and_ula_are_always_local():
    sb = SystemBackend()
    default = sb.system.get_default_network()

    assert default.is_local(IPAddress.new("fe80::1"))  # link-local
    assert default.is_local(IPAddress.new("fd12:3456:789a::1"))  # Unique Local Address
    # Globally routed IPv6 address, not covered by the (IPv4-only) default network mask
    assert not default.is_local(IPAddress.new("2001:db8::1"))


def test_dual_stack_network_mask():
    sb = SystemBackend()
    net = sb.network("Dual", ip_mask="10.1.0.0/16")
    net.mask("2001:db8::/32")

    assert net.network.is_local(IPAddress.new("10.1.0.5"))
    assert net.network.is_local(IPAddress.new("2001:db8::5"))
    assert not net.network.is_local(IPAddress.new("10.2.0.5"))
    assert not net.network.is_local(IPAddress.new("2001:db9::5"))


