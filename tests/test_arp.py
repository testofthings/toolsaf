from toolsaf.common.address import Protocol
from toolsaf.builder_backend import SystemBackend
from toolsaf.core.inspector import Inspector
from toolsaf.core.ignore_rules import IgnoreRules
from toolsaf.main import ARP
from toolsaf.common.basics import ExternalActivity
from toolsaf.common.traffic import EthernetFlow
from toolsaf.common.basics import Status


def test_serve_arp():
    sb = SystemBackend()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dev1.serve(ARP)
    dev2 = sb.device().hw("1:0:0:0:0:2")
    dev3 = sb.device().hw("1:0:0:0:0:3")
    dev3.entity.set_external_activity(ExternalActivity.UNLIMITED)
    dev4 = sb.device().hw("1:0:0:0:0:4")
    dev4 >> dev1 / ARP

    m = Inspector(sb.system, IgnoreRules())

    # dev3 can make external calls
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "1:0:0:0:0:3") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.EXTERNAL

    # dev2 not defined to make ARP calls
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "1:0:0:0:0:2") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.UNEXPECTED

    # unknown device can make ARP calls
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "1:0:0:0:1:1") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.EXTERNAL

    # dev4 can make ARP calls
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "1:0:0:0:0:4") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.EXPECTED
    # FIXME: The remaining does not work
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "1:0:0:0:0:4") << "1:0:0:0:0:1")
    # assert f1.status == Status.EXPECTED

