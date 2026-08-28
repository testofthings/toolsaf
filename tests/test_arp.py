from toolsaf.common.address import HWAddress, Protocol
from toolsaf.builder_backend import SystemBackend
from toolsaf.core.inspector import Inspector
from toolsaf.main import ARP
from toolsaf.common.basics import ExternalActivity
from toolsaf.common.traffic import Evidence, EthernetFlow
from toolsaf.core.model import EvidenceNetworkSource
from toolsaf.common.basics import Status


def test_serve_arp():
    sb = SystemBackend()
    dev1 = sb.device().hw("a:0:0:0:0:1")
    dev1.serve(ARP)
    dev2 = sb.device().hw("a:0:0:0:0:2")
    dev3 = sb.device().hw("a:0:0:0:0:3")
    dev3.entity.set_external_activity(ExternalActivity.UNLIMITED)
    dev4 = sb.device().hw("a:0:0:0:0:4")
    dev4 >> dev1 / ARP

    m = Inspector(sb.system)

    # dev3 can make external calls
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "a:0:0:0:0:3") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.EXTERNAL

    # dev2 not defined to make ARP calls
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "a:0:0:0:0:2") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.UNEXPECTED

    # unknown device can make ARP calls
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "a:0:0:0:1:1") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.EXTERNAL

    # dev1 has ARP
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "a:0:0:0:0:1") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.EXTERNAL

    # dev4 does not have ARP
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "a:0:0:0:0:4") >> "ff:ff:ff:ff:ff:ff")
    assert f1.status == Status.UNEXPECTED

    # dev1 has ARP
    f1 = m.connection(EthernetFlow.new(Protocol.ARP, "a:0:0:0:0:4") << "a:0:0:0:0:1")
    assert f1.status == Status.EXPECTED


def test_arp_to_self_only_one_connection():
    sb = SystemBackend()
    dev = sb.device().ip("10.42.0.138").serve(ARP)
    system = sb.system
    m = Inspector(system)

    hw = HWAddress.new("38:2c:e5:0f:31:89")
    conn = None
    for label in ["pcap-1", "pcap-2"]:  # each evidence source is matched separately
        source = EvidenceNetworkSource("test", label=label, address_map={hw: dev.entity})
        # second flow is the connection we already know
        conn = m.connection(EthernetFlow(Evidence(source), hw, hw, protocol=Protocol.ARP)) or conn
    assert conn is not None

    # the ARP announcement is one connection, in addition to the ARP broadcast from the DSL
    conns = system.get_connections(relevant_only=False)
    assert [c.long_name() for c in conns] == ["Device ARP => ff:ff:ff:ff:ff:ff ARP",
                                              "Device ARP => 38:2c:e5:0f:31:89"]
    assert conn in conns
    addresses = [c.get_system_address().get_parseable_value() for c in conns]
    assert len(addresses) == len(set(addresses))
