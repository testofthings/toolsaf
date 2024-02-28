import pathlib
from tcsfw.address import HWAddress, IPAddress
from tcsfw.basics import Verdict
from tcsfw.builder_backend import SystemBackend
from tcsfw.event_logger import EventLogger
from tcsfw.inspector import Inspector
from tcsfw.main import DHCP, UDP
from tcsfw.matcher import SystemMatcher
from tcsfw.pcap_reader import PCAPReader
from tcsfw.traffic import IPFlow
from tcsfw.verdict import Status


def test_dhcp():
    sb = SystemBackend()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dhcp = sb.any().name("X") / DHCP
    c1 = dev1 >> dhcp
    m = SystemMatcher(sb.system)

    assert (dev1 / UDP(port=68)).entity.client_side

    f1 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "0.0.0.0", 68) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 67))
    f2 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 68) << ("1:0:0:0:0:2", "192.168.0.2", 67))

    assert c1.connection.source == (dev1 / UDP(port=68)).entity
    assert c1.connection.target == dhcp.entity

    assert f1 == c1.connection
    assert f2 == c1.connection

    assert dev1.entity.addresses == {HWAddress.new("1:0:0:0:0:1"), IPAddress.new("192.168.0.1")}

    # IP reassigned
    f3 = m.connection(IPFlow.UDP("1:0:0:0:0:5", "0.0.0.0", 68) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 67))
    h2 = sb.system.get_endpoint(HWAddress.new("1:0:0:0:0:5"))
    assert h2.name == "01:00:00:00:00:05"
    assert f3.source.get_parent_host() == h2
    assert f3.target == dhcp.entity
    f4 = m.connection(IPFlow.UDP("1:0:0:0:0:5", "192.168.0.1", 68) << ("1:0:0:0:0:2", "192.168.0.2", 67))
    assert f4 == f3

    assert dev1.entity.addresses == {HWAddress.new("1:0:0:0:0:1")}
    assert h2.addresses == {HWAddress.new("1:0:0:0:0:5"), IPAddress.new("192.168.0.1")}
    assert h2.name == "192.168.0.1"  # renamed

    assert f1 != f3
    assert f2 != f4

    # reminder: inspector changes verdicts
    assert f1.status == Status.EXPECTED
    assert f2.status == Status.EXPECTED
    assert f3.status == Status.EXTERNAL
    assert f4.status == Status.EXTERNAL

    # one more time...
    # IP reassigned
    m.connection(IPFlow.UDP("1:0:0:0:0:6", "0.0.0.0", 68) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 67))
    h3 = sb.system.get_endpoint(HWAddress.new("1:0:0:0:0:6"))
    assert h3.name == "01:00:00:00:00:06"
    m.connection(IPFlow.UDP("1:0:0:0:0:6", "192.168.0.1", 68) << ("1:0:0:0:0:2", "192.168.0.2", 67))

    assert dev1.entity.addresses == {HWAddress.new("1:0:0:0:0:1")}
    assert h2.addresses == {HWAddress.new("1:0:0:0:0:5")}
    assert h2.name == "192.168.0.1 1"
    assert h3.addresses == {HWAddress.new("1:0:0:0:0:6"), IPAddress.new("192.168.0.1")}
    assert h3.name == "192.168.0.1 2"

def test_unexpected_dhcp_matching():
    sb = SystemBackend()
    dhcp = sb.any() / DHCP
    other = sb.broadcast(UDP(port=7777))
    dev = sb.device().hw("30:c6:f7:52:db:5c")
    dev >> dhcp
    m = EventLogger(Inspector(sb.system))
    s = sb.system

    # not the expected connection - should still have target DHCP
    c0 = m.connection(IPFlow.UDP("30:c6:f7:52:db:00", "192.168.0.10", 68) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 67))
    assert c0.status == Status.UNEXPECTED
    # assert c0.target == dhcp.entity  # ... creates new entity


def test_from_pcap():
    sb = SystemBackend()
    other = sb.broadcast(UDP(port=7777))
    dhcp = sb.any() / DHCP
    dev = sb.device().hw("30:c6:f7:52:db:5c")
    dev >> dhcp
    m = EventLogger(Inspector(sb.system))
    s = sb.system

    PCAPReader.inspect(pathlib.Path("tests/samples/pcap/dhcp.pcap"), m)

    cos = s.get_connections()
    assert len(cos) == 2
    assert cos[0].status == Status.EXPECTED
    assert cos[1].status == Status.EXPECTED

def test_from_pcap2():
    sb = SystemBackend()
    dhcp = sb.any() / DHCP
    dev1 = sb.device().hw("30:c6:f7:52:db:5c")
    dev1 >> dhcp

    # learn address (not sure how this happens), messes broadcast matching unless is_any == True
    dhcp.entity.get_parent_host().addresses.add(IPAddress.new("192.168.1.15"))

    m = EventLogger(Inspector(sb.system))
    s = sb.system

    # learn on address for DHCP
    PCAPReader.inspect(pathlib.Path("tests/samples/pcap/dhcp.pcap"), m)

    cos = s.get_connections()
    assert len(cos) == 2
    assert cos[0].status == Status.EXPECTED
    assert cos[1].status == Status.EXPECTED

