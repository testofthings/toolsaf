"""Test port range matching"""

from toolsaf.builder_backend import SystemBackend
from toolsaf.common.basics import ExternalActivity, Status
from toolsaf.common.traffic import IPFlow
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



