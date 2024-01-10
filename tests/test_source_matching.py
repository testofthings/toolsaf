from tcsfw.main import SystemBuilder, UDP
from tcsfw.matcher import SystemMatcher
from tcsfw.traffic import IPFlow, Evidence


def test_source_matching():
    sb = SystemBuilder()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    m = SystemMatcher(sb.system)

    source2 = sb.load().hw(dev1, "1:0:0:0:1:1")
    e2 = Evidence(source2.get_source())

    c1 = m.connection(
        (IPFlow.UDP("1:0:0:0:1:1", "192.168.11.2", 2000) >> ("1:0:0:0:0:2", "192.168.20.10", 1001)).set_evidence(e2))

    c2 = m.connection(
        (IPFlow.UDP("1:0:0:0:1:1", "192.168.11.2", 2000) >> ("1:0:0:0:0:2", "192.168.20.10", 1001)))

    c3 = m.connection(
        (IPFlow.UDP("1:0:0:0:0:1", "192.168.11.2", 2000) >> ("1:0:0:0:0:2", "192.168.20.10", 1001)))

    assert c1.source == dev1.entity
    assert c2.source != dev1.entity
    assert c3.source == dev1.entity
