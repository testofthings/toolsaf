"""Test port range matching"""

from toolsaf.builder_backend import SystemBackend
from toolsaf.common.basics import ExternalActivity, Status
from toolsaf.common.traffic import IPFlow
from toolsaf.core.address_ranges import PortRange
from toolsaf.core.matcher import SystemMatcher
from toolsaf.core.matcher_engine import MatcherEngine
from toolsaf.main import UDP


def test_port_range_matching():
    sb = SystemBackend()
    dev0 = sb.device("Dev0").ip("120.0.0.1")
    dev0.external_activity(ExternalActivity.OPEN)
    s0 = dev0 / UDP().port_range(1000, 2000).ports(2500)
    s1 = dev0 / UDP().port_range(2200, 2499).ports(3000, 3001)

    assert str(s0.entity.port_range) == "1000-2000,2500"
    assert str(s1.entity.port_range) == "2200-2499,3000,3001"

    assert s0.entity.name == "UDP:1000...2500"
    assert s1.entity.name == "UDP:2200...3001"

    m = SystemMatcher(sb.system)

    flow = IPFlow.UDP("10:0:0:0:0:1", "120.0.0.2", 1100) >> ("10:0:0:0:0:2", "120.0.0.1", 1001)
    con = m.connection(flow)
    assert con.target == s0.entity

    flow = IPFlow.UDP("10:0:0:0:0:1", "120.0.0.2", 1100) >> ("10:0:0:0:0:2", "120.0.0.1", 3001)
    con = m.connection(flow)
    assert con.target == s1.entity

    flow = IPFlow.UDP("10:0:0:0:0:1", "120.0.0.2", 1100) >> ("10:0:0:0:0:2", "120.0.0.1", 2100)
    con = m.connection(flow)
    assert con.target == dev0.entity


def test_port_range_serialization():
    pr = PortRange.parse_port_range("1000-2000,2500,3000-3500")
    assert pr.get_parseable_value() == "1000-2000,2500,3000-3500"

def test_port_range_single_port():
    pr = PortRange.parse_port_range("8080")
    assert str(pr) == "8080"
    assert pr.is_match(8080)
    assert not pr.is_match(8081)

def test_port_range_multiple_ports_and_ranges():
    pr = PortRange.parse_port_range("1000-1002,2000,3000-3002")
    assert str(pr) == "1000-1002,2000,3000-3002"
    for port in [1000, 1001, 1002, 2000, 3000, 3001, 3002]:
        assert pr.is_match(port)
    assert not pr.is_match(999)
    assert not pr.is_match(2001)
    assert not pr.is_match(2999)

def test_port_range_invalid_input():
    try:
        PortRange.parse_port_range("")
        assert False, "Should raise ValueError"
    except ValueError:
        pass
    try:
        PortRange.parse_port_range("abc")
        assert False, "Should raise ValueError"
    except ValueError:
        pass
    try:
        PortRange.parse_port_range("1000-2000,1500-2500")
        assert False, "Should raise ValueError"
    except ValueError:
        pass

def test_port_range_repr_and_eq():
    pr1 = PortRange.parse_port_range("1000-2000,2500")
    pr2 = PortRange.parse_port_range("1000-2000,2500")
    pr3 = PortRange.parse_port_range("1000-2000")
    assert pr1 == pr2
    assert pr1 != pr3
