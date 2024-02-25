from tcsfw.builder_backend import SystemBackend
from tcsfw.main import HTTP, UDP
from tcsfw.matcher import SystemMatcher
from tcsfw.traffic import IPFlow, Evidence


def test_source_matching():
    sb = SystemBackend()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    m = SystemMatcher(sb.system)

    source2 = sb.load().traffic().hw(dev1, "1:0:0:0:1:1")
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


def test_null_address_matching():
    sb = SystemBackend()
    dev1 = sb.device().ip("192.168.11.1")
    ser2 = sb.device().ip("10.10.10.12") / HTTP
    dev1 >> ser2
    m = SystemMatcher(sb.system)

    c1 = m.connection(
        (IPFlow.TCP("00:00:00:00:00:00", "192.168.11.1", 10000) >> ("00:00:00:00:00:00", "10.10.10.12", 80)))
    assert c1.source == dev1.entity
    assert c1.target == ser2.entity

    c2 = m.connection(
        (IPFlow.TCP("00:00:00:00:00:00", "192.168.11.2", 10000) >> ("00:00:00:00:00:00", "10.10.10.12", 80)))
    assert c2.source.long_name() == "192.168.11.2"  # Null address is not real
    assert c2.target == ser2.entity
