from tcsfw.address import Addresses, IPAddress
from tcsfw.builder_backend import SystemBackend
from tcsfw.matcher import SystemMatcher
from tcsfw.model import EvidenceNetworkSource
from tcsfw.traffic import Evidence, IPFlow
from tcsfw.basics import Status


def test_source_ip():
    sb = SystemBackend()
    dev0 = sb.device().ip("12.0.0.1")
    assert Addresses.get_prioritized(dev0.entity.addresses).is_global()

    m = SystemMatcher(sb.system)
    flow = IPFlow.UDP("1:0:0:0:0:1", "12.0.0.1", 1100) >> ("1:0:0:0:0:2", "12.0.0.2", 1234)
    con = m.connection(flow)
    assert con.source == dev0.entity
    assert con.target.status == Status.UNEXPECTED

    m = SystemMatcher(sb.system)
    flow = IPFlow.UDP("1:0:0:0:0:1", "22.0.0.1", 1100) >> ("1:0:0:0:0:2", "12.0.0.2", 1234)
    con = m.connection(flow)
    assert con.source.status == Status.EXTERNAL
    assert con.target.status == Status.EXTERNAL

    # match with source specific mapping
    m = SystemMatcher(sb.system)
    src = EvidenceNetworkSource("Source A")
    src.address_map[IPAddress.new("22.0.0.1")] = dev0.entity
    flow = flow.new_evidence(Evidence(src))
    con = m.connection(flow)
    assert con.source == dev0.entity
    assert con.target.status == Status.EXTERNAL  # changed earlier to UNEXPECTED (not optimal)


def test_source_ip_2():
    sb = SystemBackend()
    dev0 = sb.device() # NOTE: No address

    flow = IPFlow.UDP("1:0:0:0:0:1", "22.0.0.1", 1100) >> ("1:0:0:0:0:2", "12.0.0.2", 1234)

    # match with source specific mapping
    m = SystemMatcher(sb.system)
    src = EvidenceNetworkSource("Source A")
    src.address_map[IPAddress.new("22.0.0.1")] = dev0.entity
    flow = flow.new_evidence(Evidence(src))
    con = m.connection(flow)
    assert con.source == dev0.entity  # No address, matching did fails
    assert con.target.status == Status.UNEXPECTED


def test_target_ip():
    sb = SystemBackend()
    dev0 = sb.device().ip("12.0.0.2")
    assert Addresses.get_prioritized(dev0.entity.addresses).is_global()

    m = SystemMatcher(sb.system)
    flow = IPFlow.UDP("1:0:0:0:0:1", "12.0.0.1", 1100) >> ("1:0:0:0:0:2", "12.0.0.2", 1234)
    con = m.connection(flow)
    assert con.source.status == Status.UNEXPECTED
    assert con.target == dev0.entity

    m = SystemMatcher(sb.system)
    flow = IPFlow.UDP("1:0:0:0:0:1", "12.0.0.1", 1100) >> ("1:0:0:0:0:2", "22.0.0.2", 1234)
    con = m.connection(flow)
    assert con.source.status == Status.EXTERNAL
    assert con.target.status == Status.EXTERNAL

    # match with source specific mapping
    m = SystemMatcher(sb.system)
    src = EvidenceNetworkSource("Source A")
    src.address_map[IPAddress.new("22.0.0.2")] = dev0.entity
    flow = flow.new_evidence(Evidence(src))
    con = m.connection(flow)
    assert con.source.status == Status.EXTERNAL  # changed earlier to UNEXPECTED (not optimal)
    assert con.target == dev0.entity


def test_subnet():
    sb = SystemBackend()
    na = sb.network("NET_A", ip_mask="22.0.0.0/24")
    nb = sb.network("NET_B", ip_mask="23.0.0.0/24")
    dev1 = sb.device().ip("21.0.0.2")
    dev2 = sb.device().in_networks(na).ip("22.0.0.2")
    dev3 = sb.device().in_networks(nb).ip("23.0.0.2")
    m = SystemMatcher(sb.system)

    flow = (IPFlow.UDP("1:0:0:0:0:1", "22.0.0.1", 1100) >> ("1:0:0:0:0:2", "22.0.0.2", 1234)).at_network(na.network)
    conn = m.connection(flow)
    assert conn.target == dev2.entity

    flow = (IPFlow.UDP("1:0:0:0:0:1", "22.0.0.1", 1100) >> ("1:0:0:0:0:2", "21.0.0.2", 1234)).at_network(na.network)
    conn = m.connection(flow)
    assert conn.target != dev2.entity

    flow = (IPFlow.UDP("1:0:0:0:0:1", "23.0.0.2", 1100) >> ("1:0:0:0:0:2", "21.0.0.2", 1234)).at_network(na.network)
    conn = m.connection(flow)
    assert conn.source != dev3.entity

    flow = (IPFlow.UDP("1:0:0:0:0:1", "23.0.0.2", 1100) >> ("1:0:0:0:0:2", "21.0.0.2", 1234)).at_network(nb.network)
    conn = m.connection(flow)
    assert conn.source == dev3.entity

    flow = IPFlow.UDP("1:0:0:0:0:1", "22.0.0.1", 1100) >> ("1:0:0:0:0:2", "21.0.0.2", 1234)
    conn = m.connection(flow)
    assert conn.target == dev1.entity
    # assert Addresses.get_prioritized(dev0.entity.addresses).is_global()
