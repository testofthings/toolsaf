from tcsfw.address import HWAddress, IPAddress
from tcsfw.main import SystemBuilder, DHCP, UDP
from tcsfw.matcher import SystemMatcher
from tcsfw.traffic import IPFlow
from tcsfw.verdict import Status, Verdict


def test_dhcp():
    sb = SystemBuilder()
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

