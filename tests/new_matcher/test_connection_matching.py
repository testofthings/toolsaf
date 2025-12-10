"""Test connection matching logic"""

from toolsaf.builder_backend import SystemBackend
from toolsaf.common.address import EndpointAddress, IPAddress
from toolsaf.common.traffic import IPFlow
from toolsaf.core.matcher_engine import FlowMatcher, MatcherEngine, Weights
from toolsaf.main import TCP


def test_connection_basics():
    sb = SystemBackend()
    engine = MatcherEngine(sb.system)

    dev0 = sb.device("Dev0").ip("12.0.0.1")
    dev1 = sb.device("Dev1").ip("12.0.0.2")
    dev10 = sb.device("Dev10")
    dev11 = sb.device("Dev11")
    dev0_dev1_1234 = engine.add_connection((dev0 >> dev1 / TCP(port=1234)).connection)
    dev0_dev10_1234 = engine.add_connection((dev0 >> dev10 / TCP(port=1234)).connection)
    dev0_dev1_1011 = engine.add_connection((dev0 >> dev1 / TCP(port=1011)).connection)
    dev0_8888_dev1_1088 = engine.add_connection((dev0 / TCP(8888) >> dev1 / TCP(port=1088)).connection)
    dev1_dev0_1010 = engine.add_connection((dev1 >> dev0 / TCP(port=1010)).connection)
    dev10_dev11_2010 = engine.add_connection((dev10 >> dev11 / TCP(port=2010)).connection)

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) >> ("1:0:0:0:0:2", "12.0.0.2", 1234)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == dev0_dev1_1234
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 20123), EndpointAddress.tcp("12.0.0.2", 1234))

    # reverse direction
    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20124) << ("1:0:0:0:0:2", "12.0.0.2", 1234)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == dev0_dev1_1234
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 20124), EndpointAddress.tcp("12.0.0.2", 1234))

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) >> ("1:0:0:0:1:1", "12.0.1.1", 1234)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == dev0_dev10_1234
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 20123), EndpointAddress.tcp("12.0.1.1", 1234))

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 8888) >> ("1:0:0:0:1:1", "12.0.0.2", 1088)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == dev0_8888_dev1_1088
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 8888), EndpointAddress.tcp("12.0.0.2", 1088))

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 8888) >> ("1:0:0:0:1:1", "12.0.1.1", 2234)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == (dev0_8888_dev1_1088.source, None)
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 8888), None)

    flow = IPFlow.TCP("1:0:0:0:2:1", "12.0.2.1", 8888) >> ("1:0:0:0:1:1", "12.0.1.1", 2010)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == dev10_dev11_2010
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.2.1", 8888), EndpointAddress.tcp("12.0.1.1", 2010))


def test_connection_no_match():
    sb = SystemBackend()
    engine = MatcherEngine(sb.system)

    dev0 = sb.device("Dev0").ip("12.0.0.1")
    dev1 = sb.device("Dev1").ip("12.0.0.2")
    dev10 = sb.device("Dev10")
    dev11 = sb.device("Dev11")
    dev11_2010 = dev11 / TCP(2010)
    dev0_dev1_1234 = engine.add_connection((dev0 >> dev1 / TCP(port=1234)).connection)
    engine.add_host(dev10.entity)
    engine.add_host(dev11.entity)

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) >> ("1:0:0:0:0:2", "12.0.0.2", 888)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == (dev0.entity, dev1.entity)
    assert fm.sources.get_weight(dev0.entity) == Weights.IP_ADDRESS
    assert fm.targets.get_weight(dev1.entity) == Weights.IP_ADDRESS
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 20123), EndpointAddress.tcp("12.0.0.2", 888))

    # "reverse" direction (not really reverse, as no connection matches)
    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) << ("1:0:0:0:0:2", "12.0.0.2", 888)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == (dev1.entity, dev0.entity)
    assert fm.sources.get_weight(dev1.entity) == Weights.IP_ADDRESS
    assert fm.targets.get_weight(dev0.entity) == Weights.IP_ADDRESS
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.2", 888), EndpointAddress.tcp("12.0.0.1", 20123))

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) >> ("1:0:0:0:0:2", "55.44.33.22", 1234)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == (dev0.entity, None)
    assert fm.sources.get_weight(dev0.entity) == Weights.IP_ADDRESS
    assert fm.targets.get_weight(dev10.entity) == Weights.WILDCARD_ADDRESS
    assert fm.targets.get_weight(dev11.entity) == Weights.WILDCARD_ADDRESS
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 20123), None)

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) >> ("1:0:0:0:0:2", "55.44.33.22", 2010)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == (dev0.entity, dev11_2010.entity)
    assert fm.sources.get_weight(dev0.entity) == Weights.IP_ADDRESS
    assert fm.targets.get_weight(dev10.entity) == Weights.WILDCARD_ADDRESS
    assert fm.targets.get_weight(dev11_2010.entity) == Weights.WILDCARD_ADDRESS + Weights.PROTOCOL_PORT
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("12.0.0.1", 20123), EndpointAddress.tcp("55.44.33.22", 2010))

    # "reverse" direction
    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 9000) << ("1:0:0:0:0:2", "55.44.33.22", 2010)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == (dev11_2010.entity, dev0.entity)
    assert fm.get_host_addresses() == (
        EndpointAddress.tcp("55.44.33.22", 2010), EndpointAddress.tcp("12.0.0.1", 9000))

    flow = IPFlow.TCP("1:0:0:0:0:1", "99.0.0.1", 9000) >> ("1:0:0:0:0:2", "55.44.33.22", 2010)
    fm = FlowMatcher(engine, flow)
    conn = fm.get_connection()
    assert conn == (None, dev11_2010.entity)
    assert fm.targets.get_weight(dev10.entity) == Weights.WILDCARD_ADDRESS
    assert fm.targets.get_weight(dev11_2010.entity) == Weights.WILDCARD_ADDRESS + Weights.PROTOCOL_PORT
    assert fm.get_host_addresses() == (
        None, EndpointAddress.tcp("55.44.33.22", 2010))
