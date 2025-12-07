"""Test connection matching logic"""

from toolsaf.builder_backend import SystemBackend
from toolsaf.common.traffic import IPFlow
from toolsaf.core.model import Connection
from toolsaf.core.new_matcher import MatchEngine
from toolsaf.main import TCP


def test_connection_basics():
    sb = SystemBackend()
    engine = MatchEngine(sb.system)

    dev0 = sb.device("Dev0").ip("12.0.0.1")
    dev1 = sb.device("Dev1").ip("12.0.0.2")
    dev10 = sb.device("Dev10")
    dev11 = sb.device("Dev11")
    engine.add_entity(dev0.entity)
    engine.add_entity(dev1.entity)
    dev0_dev1_1234 = engine.add_connection((dev0 >> dev1 / TCP(port=1234)).connection)
    dev0_dev10_1234 = engine.add_connection((dev0 >> dev10 / TCP(port=1234)).connection)
    dev0_dev1_1011 = engine.add_connection((dev0 >> dev1 / TCP(port=1011)).connection)
    dev0_8888_dev1_1088 = engine.add_connection((dev0 / TCP(8888) >> dev1 / TCP(port=1088)).connection)
    dev1_dev0_1010 = engine.add_connection((dev1 >> dev0 / TCP(port=1010)).connection)
    dev10_dev11_2010 = engine.add_connection((dev10 >> dev11 / TCP(port=2010)).connection)

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) >> ("1:0:0:0:0:2", "12.0.0.2", 1234)
    state = engine.deduce_flow(flow)
    conn = state.get_top_item(Connection)
    assert conn == dev0_dev1_1234

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20123) >> ("1:0:0:0:1:1", "12.0.1.1", 1234)
    state = engine.deduce_flow(flow)
    conn = state.get_top_item(Connection)
    # assert conn == dev0_dev10_1234

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 8888) >> ("1:0:0:0:1:1", "12.0.1.1", 2234)
    state = engine.deduce_flow(flow)
    conn = state.get_top_item(Connection)
    assert conn == dev0_8888_dev1_1088

    flow = IPFlow.TCP("1:0:0:0:2:1", "12.0.2.1", 8888) >> ("1:0:0:0:1:1", "12.0.1.1", 2010)
    state = engine.deduce_flow(flow)
    conn = state.get_top_item(Connection)
    # assert conn == dev10_dev11_2010

    flow = IPFlow.TCP("1:0:0:0:0:1", "12.0.0.1", 20124) << ("1:0:0:0:0:2", "12.0.0.2", 1234)
    state = engine.deduce_flow(flow)
    conn = state.get_top_item(Connection)
    assert conn == dev0_dev1_1234

