from tcsfw.address import HWAddress, Protocol, HWAddresses
from tcsfw.verdict import Verdict
from tcsfw.builder_backend import SystemBackend
from tcsfw.inspector import Inspector
from tcsfw.main import ICMP, UDP, ARP, EAPOL
from tcsfw.traffic import IPFlow, EthernetFlow, NO_EVIDENCE
from tcsfw.basics import Status


def test_icmp():
    sb = SystemBackend()
    dev1 = sb.device().ip("1.0.1.1") / ICMP
    dev1 >> sb.device().ip("1.0.1.2") / UDP(port=2000)  # this used to steal icmp() endpoint
    i = Inspector(sb.system)

    cs = i.connection(IPFlow.IP("11:02:03:04:05:06", "1.0.0.1", 1) >> ("01:02:03:04:05:06", "1.0.1.1", 1))
    assert cs.source.name == "1.0.0.1"
    assert cs.target.name == "ICMP"
    assert cs.target == dev1.entity
    assert cs.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs.source.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs.target.status_verdict() == (Status.EXPECTED, Verdict.INCON)

    cs = i.connection(IPFlow.IP("11:02:03:04:05:06", "1.0.0.1", 2) >> ("01:02:03:04:05:06", "1.0.1.1", 2))
    assert cs.source.name == "1.0.0.1"
    assert cs.target == dev1.entity.get_parent_host()
    assert cs.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert cs.source.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs.target.status_verdict() == (Status.EXPECTED, Verdict.INCON)

    cs = i.connection(IPFlow.IP("11:02:03:04:05:06", "1.0.0.1", 1) << ("01:02:03:04:05:06", "1.0.1.1", 1))
    assert cs.source.name == "1.0.0.1"
    assert cs.target.name == "ICMP"
    assert cs.target == dev1.entity
    assert cs.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs.source.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs.target.status_verdict() == (Status.EXPECTED, Verdict.PASS)



def test_arp():
    sb = SystemBackend()
    dev1 = sb.device().hw("01:02:03:04:05:06")
    arp1 = dev1 / ARP  # the broadcast service
    i = Inspector(sb.system)

    ev = NO_EVIDENCE

    # ARP query
    cs = i.connection(EthernetFlow(ev, HWAddress.new("21:02:03:04:05:06"), HWAddress.new("01:02:03:04:05:06"),
                                   protocol=Protocol.ARP))
    assert cs.source.name == "21:02:03:04:05:06"
    assert cs.target.name == "ARP"
    assert cs.target.get_parent_host() == dev1.entity
    assert cs.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs.source.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs.target.status_verdict() == (Status.EXPECTED, Verdict.INCON)
    # response
    cs2 = i.connection(EthernetFlow(ev, HWAddress.new("01:02:03:04:05:06"), HWAddress.new("21:02:03:04:05:06"),
                                    protocol=Protocol.ARP))
    assert cs2 == cs

    # broadcast
    cs = i.connection(EthernetFlow(ev, HWAddress.new("01:02:03:04:05:06"), HWAddresses.BROADCAST,
                                   protocol=Protocol.ARP))
    assert cs.source.name == "ARP"
    assert cs.source.get_parent_host() == dev1.entity
    assert cs.target.name == "ARP"
    assert cs.target.get_parent_host().name == "ff:ff:ff:ff:ff:ff"
    assert cs.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert cs.source.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert cs.target.status_verdict() == (Status.EXPECTED, Verdict.PASS)

    # NOTE: This will not match, should it? No!
    cs = i.connection(EthernetFlow(ev, HWAddress.new("21:02:03:04:05:06"), HWAddress.new("01:02:03:04:05:06"),
                                   payload=0x0806))
    assert cs.source.name == "21:02:03:04:05:06"
    assert cs.target == dev1.entity
    assert cs.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)


def test_eapol_name():
    sb = SystemBackend()
    dev1 = sb.device().hw("01:02:03:04:05:06")
    s = dev1 / EAPOL
    assert s.entity.name == "EAPOL"


