from tdsaf.address import AddressEnvelope, EndpointAddress, EntityTag, Protocol, DNSName, IPAddress, HWAddress
from tdsaf.inspector import Inspector
from tdsaf.model import Host, IoTSystem
from tdsaf.verdict import Verdict
from tdsaf.builder_backend import SystemBackend
from tdsaf.main import TCP, UDP, SSH
from tdsaf.matcher import SystemMatcher
from tdsaf.basics import ExternalActivity
from tdsaf.traffic import IPFlow
from tdsaf.basics import Status


class Setup:
    """Testing setup"""
    def __init__(self):
        self.system = SystemBackend()

    def get_system(self) -> IoTSystem:
        """Get system"""
        return self.system.system

    def get_inspector(self):
        """Get inspector"""
        return Inspector(self.get_system())

    def get_hosts(self):
        """Get hosts"""
        return [c for c in self.get_system().children if isinstance(c, Host)]

    def get_connections(self):
        """Get connections"""
        return self.get_system().get_connections()


def simple_setup_1(external=False) -> SystemBackend:
    sb = SystemBackend()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dev2 = sb.device().ip("192.168.0.2")
    dev3 = sb.device()
    dev1 >> dev2 / UDP(port=1234)
    if external:
        dev4 = sb.device().hw("1:0:0:1:0:4")
        dev4.external_activity(ExternalActivity.UNLIMITED)
    return sb


def simple_setup_2() -> SystemBackend:
    sb = SystemBackend()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dev2 = sb.device().name("target.org")
    dev3 = sb.device()
    dev1 >> dev2 / UDP(port=1234)
    return sb


def test_tags():
    su = Setup()
    dev1 = su.system.device().hw("1:0:0:0:0:1")
    assert EntityTag("Device") in dev1.entity.addresses
    assert dev1.entity.get_tag() == EntityTag("Device")

    dev2 = su.system.device().hw("1:0:0:0:0:2")
    assert EntityTag("Device") in dev1.entity.addresses
    assert EntityTag("Device_2") in dev2.entity.addresses
    assert dev2.entity.get_tag() == EntityTag("Device_2")

    dev3 = su.system.device("Doe Hot")
    assert EntityTag("Doe_Hot") in dev3.entity.addresses
    assert dev3.entity.get_tag() == EntityTag("Doe_Hot")

    c0 = dev1 >> dev3 / TCP(1234)
    c0_tag = c0.connection.get_tag()
    assert c0_tag == (EntityTag("Device"), EndpointAddress(EntityTag("Doe_Hot"), Protocol.TCP, 1234))


def test_connection_match():
    sb = simple_setup_1()
    m = SystemMatcher(sb.system)

    cs = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs is not None
    assert cs.status == Status.EXPECTED
    assert cs.source.name == "Device 1"
    assert cs.target.name == "UDP:1234"

    cs = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs is not None
    assert cs.status == Status.EXPECTED
    assert cs.source.name == "Device 1"
    assert cs.target.name == "UDP:1234"

    flow = IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234)
    cs = m.connection(flow)
    assert cs is not None
    assert cs.status == Status.UNEXPECTED
    assert cs.source.name == "Device 1"
    assert cs.target.name == "1.0.0.3"

    # connection between unexpected hosts
    cs = m.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 2004) >> ("1:0:0:0:0:5", "1.0.0.5", 2005))
    assert cs is not None
    assert cs.status == Status.EXTERNAL
    assert cs.source.name == "01:00:00:00:00:04"
    assert cs.target.name == "1.0.0.5"

    cs = m.connection(IPFlow.UDP("1:0:0:0:0:6", "1.0.0.6", 2006) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs is not None
    assert cs.status == Status.UNEXPECTED
    assert cs.source.name == "1.0.0.6"
    assert cs.target.name == "UDP:1234"

    c_list = m.system.get_connections()
    c_sts = [c.status for c in c_list]
    assert c_sts == [Status.EXPECTED, Status.UNEXPECTED, Status.EXPECTED, Status.UNEXPECTED]


def test_match_mix_unknown():
    sb = simple_setup_1()
    m = SystemMatcher(sb.system)

    cs1 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1101) >> ("1:0:0:0:0:3", "192.168.0.3", 1234))
    cs2 = m.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 1102) >> ("1:0:0:0:0:3", "192.168.0.3", 1234))
    cs3 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1103) >> ("1:0:0:0:0:3", "192.168.0.3", 1234))
    cs4 = m.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 1104) >> ("1:0:0:0:0:3", "192.168.0.3", 1234))
    cs4_2 = m.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 1104) << ("1:0:0:0:0:3", "192.168.0.3", 1234))
    cs5 = m.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 1105) >> ("1:0:0:0:0:3", "192.168.0.3", 2000))
    cs6 = m.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 1106) >> ("1:0:0:0:0:3", "192.168.0.3", 1234))
    cs7 = m.connection(IPFlow.UDP("1:0:0:0:0:7", "192.168.0.7", 1107) >> ("1:0:0:0:0:3", "192.168.0.3", 1234))

    assert cs1 == cs3
    assert cs2 == cs4
    assert cs4_2 == cs2
    assert cs1 != cs2
    assert cs5 != cs4
    assert cs6 == cs2
    assert cs7 != cs2

    # all observed connectinos are unexpected or external
    assert all([c.status == Status.UNEXPECTED for c in [cs1, cs3]])
    assert all([c.status == Status.EXTERNAL for c in [cs2, cs4, cs4_2, cs5, cs6, cs7]])

    assert cs1.source.name == "Device 1"
    assert cs1.target.name == "01:00:00:00:00:03"
    assert cs2.source.name == "01:00:00:00:00:04"
    assert cs2.target.name == "UDP:1234"  # because there was reply
    assert cs7.source.name == "01:00:00:00:00:07"
    assert cs7.target.name == "UDP:1234"

    dev1 = sb.system.get_endpoint(HWAddress.new("1:0:0:0:0:1"))
    assert dev1.get_expected_verdict() == Verdict.INCON  # would be updated by inspector
    dev_s = sb.system.get_endpoint(HWAddress.new("1:0:0:0:0:3")).get_entity("UDP:1234")
    assert dev_s == cs2.target
    assert dev_s.get_expected_verdict() == Verdict.INCON  # would be updated by inspector
    dev4 = sb.system.get_endpoint(HWAddress.new("1:0:0:0:0:4"))
    assert dev4 == cs2.source
    assert dev4.get_expected_verdict() == Verdict.INCON
    dev7 = sb.system.get_endpoint(HWAddress.new("1:0:0:0:0:7"))
    assert dev7 == cs7.source
    assert dev7.get_expected_verdict() == Verdict.INCON

    assert cs1 in dev1.connections
    assert cs1 not in dev_s.get_parent_host().connections
    assert cs2 in dev_s.get_parent_host().connections  # replied
    assert cs7 not in dev_s.get_parent_host().connections


def test_match_overlap_unknowns():
    sb = simple_setup_1()
    m = SystemMatcher(sb.system)

    m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1001) >> ("1:0:0:0:0:3", "192.168.0.3", 2001))
    m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1001) >> ("1:0:0:0:0:3", "192.168.0.3", 2002))
    m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1002) >> ("1:0:0:0:0:3", "192.168.0.3", 2001))
    m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1002) >> ("1:0:0:0:0:3", "192.168.0.3", 2002))
    # one reply
    m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1001) << ("1:0:0:0:0:3", "192.168.0.3", 2002))

    cs1, cs2, cs3, cs4, cs5 = m.system.connections.values()

    assert cs1 == cs3
    assert cs2 == cs4
    assert cs2 == cs5
    assert cs1 != cs2

    assert cs1.target.name == "01:00:00:00:00:03"
    assert cs2.target.name == "UDP:2002"

    cs11 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1001) >> ("1:0:0:0:0:3", "192.168.0.3", 2001))
    cs12 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1001) >> ("1:0:0:0:0:3", "192.168.0.3", 2002))
    cs13 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1001) >> ("1:0:0:0:0:3", "192.168.0.3", 2003))
    cs14 = m.connection(IPFlow.UDP("1:0:0:0:0:2", "192.168.0.2", 1001) >> ("1:0:0:0:0:3", "192.168.0.3", 2002))

    assert cs11 == cs1
    assert cs12 == cs2
    assert cs13 == cs1
    assert cs14 != cs1
    assert cs14.target.name == "UDP:2002"


def test_match_local_and_remote():
    sb = simple_setup_1()
    m = SystemMatcher(sb.system)

    # unknown local first
    cs01 = m.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1001) >> ("1:0:0:0:3:1", "192.168.1.1", 2001))
    cs02 = m.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1001) >> ("1:0:0:0:3:1", "19.168.3.2", 2002))

    # unknown remote first
    cs11 = m.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1001) >> ("1:0:0:0:2:1", "19.168.2.2", 2002))
    cs12 = m.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1001) >> ("1:0:0:0:2:1", "192.168.1.1", 2001))

    # known local first
    cs21 = m.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1001) >> ("1:0:0:0:0:1", "192.168.0.1", 2001))
    cs22 = m.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1001) >> ("1:0:0:0:0:1", "19.168.0.2", 2002))

    assert cs01.target.name == "01:00:00:00:03:01"
    assert cs02.target.name == "19.168.3.2"
    assert cs11.target.name == "19.168.2.2"
    assert cs12.target.name == "01:00:00:00:02:01"
    assert cs21.target.name == "Device 1"
    assert cs22.target.name == "19.168.0.2"


def test_reverse_connection_first():
    sb = simple_setup_1()
    m = SystemMatcher(sb.system)

    cs = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs is not None
    assert cs.get_expected_verdict() == Verdict.INCON
    assert cs.source.name == "Device 1"
    assert cs.target.name == "UDP:1234"


def test_host_merging():
    sb = simple_setup_2()
    m = SystemMatcher(sb.system)

    # connection to unknown host
    cs = m.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "1.0.0.2", 1234))
    assert cs.status == Status.UNEXPECTED
    assert cs.source.name == "Device 1"
    assert cs.target.name == "1.0.0.2"

    key = EndpointAddress(HWAddress.new("1:0:0:0:0:1"), Protocol.UDP, 1100), \
        EndpointAddress.ip("1.0.0.2", Protocol.UDP, 1234)
    connections = sb.system.connections
    assert connections[key] == cs

    # ...but we learn it is known
    sb.system.learn_named_address(DNSName("target.org"), IPAddress.new("1.0.0.2"))
    # the same connection remains also afterwards, also the verdict
    assert sb.system.connections[key] == cs
    assert cs.status == Status.UNEXPECTED
    assert cs.source.name == "Device 1"
    # FIXME: Connection redirection removed, matcher etc. not keeping up with it
    # assert cs.target.name == "target.org"


def test_unknown_multicast():
    sb = SystemBackend()
    m = SystemMatcher(sb.system)

    cs1 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1100) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 1234))
    cs2 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1100) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 1234))
    cs3 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1100) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 1234))

    assert cs1 == cs2
    assert cs1 == cs3

    assert cs1.source.is_host()
    assert cs1.source.name == "01:00:00:00:00:01"
    assert cs1.target.is_host()  # no longer create services for broadcast targets
    assert cs1.target.name == "255.255.255.255"

    cs4 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:2", "192.168.0.2", 1100) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 1234))

    assert cs1 != cs4

    cs5 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1100) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 2111))
    assert cs1 == cs5

    hs = sb.system.get_hosts()
    assert len(hs) == 3

    h = sb.system.get_endpoint(IPAddress.new("255.255.255.255"))
    assert set([e.name for e in h.children]) == set()


def test_unknown_ip_protocol():
    sb = simple_setup_1()
    dev1 = sb.system.get_endpoint(HWAddress.new("1:0:0:0:0:1"))
    dev2 = sb.system.get_endpoint(IPAddress.new("192.168.0.2"))
    m = SystemMatcher(sb.system)

    cs1 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1) >> ("1:0:0:0:0:2", "192.168.0.2", 1))
    assert cs1.status == Status.UNEXPECTED
    assert cs1.source == dev1
    assert cs1.target == dev2

    # reply, create new service
    cs2 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1) << ("1:0:0:0:0:2", "192.168.0.2", 1))
    assert cs2.status == Status.UNEXPECTED
    assert cs2.source == dev1
    assert cs2.target.parent == dev2
    assert cs2.target.name == "UDP:1"


def test_external_connection():
    sb = simple_setup_1()
    dev2 = sb.system.get_endpoint(IPAddress.new("192.168.0.2"))
    dev2.set_external_activity(ExternalActivity.UNLIMITED)
    m = SystemMatcher(sb.system)

    # unknown source to known port
    cs1 = m.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = m.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs1 == cs2
    assert cs1.get_expected_verdict() == Verdict.INCON
    assert cs1.source.status_verdict() == (Status.EXTERNAL, Verdict.INCON)  # no inspector to update
    assert cs1.target.status_verdict() == (Status.EXPECTED, Verdict.INCON)

    # unknown source to unknown port
    cs3 = m.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) >> ("1:0:0:0:0:2", "192.168.0.2", 2001))
    cs4 = m.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) << ("1:0:0:0:0:2", "192.168.0.2", 2001))
    assert cs3 == cs4
    assert cs4.get_expected_verdict() == Verdict.INCON
    assert cs4.source.status_verdict() == (Status.EXTERNAL, Verdict.INCON)  # no inspector to update
    assert cs4.target.status_verdict() == (Status.EXTERNAL, Verdict.INCON)

    # known host to unknown host
    cs5 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:2", "192.168.10.2", 8000) >> ("30:0:0:0:0:4", "192.168.0.4", 2001))
    assert cs5.get_expected_verdict() == Verdict.INCON
    assert cs5.source.status_verdict() == (Status.EXTERNAL, Verdict.INCON)
    assert cs5.target.status_verdict() == (Status.EXTERNAL, Verdict.INCON)


def test_wildcard_source():
    sb = SystemBackend()
    user = sb.browser()  # no address
    server = sb.backend().ip("203.0.113.1")
    ssh = server / SSH()
    user >> ssh
    m = SystemMatcher(sb.system)

    cs1 = m.connection(IPFlow.TCP(
        "1:0:0:0:0:1", "192.168.10.1", 2000) >> ("1:0:0:0:0:2", "203.0.113.1", 22))
    assert cs1.source == user.entity
    assert cs1.target == ssh.entity
    assert cs1.get_expected_verdict() == Verdict.INCON


def test_any_host():
    sb = SystemBackend()
    any1 = sb.any().name("ANY")  # no address
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dev1 >> any1 / UDP(port=1001)
    dev1 >> any1 / UDP(port=1002)
    dev1 >> any1 / UDP(port=1003)
    m = SystemMatcher(sb.system)

    cs1 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.10.1", 2000) >> ("1:0:0:0:0:2", "192.168.20.10", 1001))
    assert cs1.status == Status.EXPECTED
    assert cs1.source == dev1.entity
    assert cs1.target.parent == any1.entity

    cs2 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.10.1", 2001) >> ("1:0:0:0:0:2", "192.168.20.11", 1003))
    assert cs2.status == Status.EXPECTED
    assert cs2.source == dev1.entity
    assert cs2.target.parent == any1.entity

    cs3 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.10.1", 2002) >> ("1:0:0:0:0:2", "192.168.20.10", 1002))
    assert cs3.status == Status.EXPECTED
    assert cs3.source == dev1.entity
    assert cs3.target.parent == any1.entity

    # Fail mode: ANY now tolerates connections from unknown parties
    cs4 = m.connection(IPFlow.UDP(
        "1:0:0:0:0:5", "192.168.10.5", 2002) >> ("1:0:0:0:0:2", "192.168.20.10", 1003))
    assert cs4.status == Status.EXTERNAL
    assert cs4.source.name == "01:00:00:00:00:05"
    assert cs4.target.name == "UDP:1003"

    cs5, sad, tad, reply = m.connection_w_ends(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.10.1", 2002) >> ("1:0:0:0:0:2", "192.168.20.10", 1004))
    assert cs5.status == Status.UNEXPECTED
    assert cs5.source == dev1.entity
    assert cs5.target.name == "01:00:00:00:00:02"  # not the any()
    assert sad == EndpointAddress.hw("1:0:0:0:0:1", Protocol.UDP, 2002)
    assert tad == EndpointAddress.hw("1:0:0:0:0:2", Protocol.UDP, 1004)

    # global IP - same HW (must be unknown gateway)
    cs6, sad, tad, reply = m.connection_w_ends(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.10.1", 2002) >> ("1:0:0:0:0:2", "22.168.20.10", 1002))
    assert cs6.status == Status.EXPECTED
    assert cs6.source == dev1.entity
    assert cs6.target.parent == any1.entity
    assert sad == EndpointAddress.hw("1:0:0:0:0:1", Protocol.UDP, 2002)
    assert tad == EndpointAddress.ip("22.168.20.10", Protocol.UDP, 1002)


def test_match_preferences():
    sb = SystemBackend()
    p4 = sb.device("P4")                                 # match anything
    p3 = sb.device("P3").serve(UDP(2000))                # match port
    p2 = sb.device("P2").ip("1.0.0.1")                   # match address
    p1 = sb.device("P1").ip("1.0.0.2").serve(UDP(2002))  # match address and port
    m = SystemMatcher(sb.system)

    # match P1 service
    c = m.connection(IPFlow.UDP(
      "1:0:0:0:0:1", "192.168.10.1", 4000) >> ("1:0:0:0:0:2", "1.0.0.2", 2002))
    assert c.target.parent == p1.entity

    # match P1 host
    c = m.connection(IPFlow.UDP(
      "1:0:0:0:0:1", "192.168.10.1", 4000) >> ("1:0:0:0:0:2", "1.0.0.2", 2001))
    assert c.target == p1.entity

    # matched P1, not P3 wildcard service
    c = m.connection(IPFlow.UDP(
      "1:0:0:0:0:1", "192.168.10.1", 4000) >> ("1:0:0:0:0:2", "1.0.0.2", 2000))
    assert c.target == p1.entity

    c = m.connection(IPFlow.UDP(
      "1:0:0:0:0:2", "192.168.10.2", 4000) >> ("1:0:0:0:0:2", "1.0.0.1", 2000))
    assert c.target == p2.entity

    c = m.connection(IPFlow.UDP(
      "1:0:0:0:0:1", "192.168.10.1", 4000) >> ("1:0:0:0:0:2", "1.0.0.1", 2001))
    assert c.target == p2.entity

    c = m.connection(IPFlow.UDP(
      "1:0:0:0:0:1", "192.168.10.1", 4000) >> ("1:0:0:0:0:2", "1.0.0.3", 2001))
    assert c.target.name == "1.0.0.3"


def test_reply_misinterpretation():
    sb = SystemBackend()
    dev = sb.device().hw("1:0:0:0:0:1")
    m = SystemMatcher(sb.system)

    c0 = m.connection(IPFlow.UDP(
      "1:0:0:0:0:2", "192.168.0.2", 4000) >> ("1:0:0:0:0:1", "192.168.0.1", 2001))

    # this it NOT a reply, but unfortunate ICMP
    c1 = m.connection(IPFlow.IP(
        "1:0:0:0:0:2", "192.168.0.2", 1) << ("1:0:0:0:0:1", "192.168.0.1", 1))

    assert c0 != c1


def test_pick_service_from_subnet():
    su = Setup()
    net1 = su.system.network("VPN", "169.254.0.0/16")
    dev1 = su.system.device().in_networks(net1, su.system.network()).ip("192.168.4.5")

    ins = su.get_inspector()
    addr = AddressEnvelope(
        address=IPAddress.new("192.168.4.5"),
        content=EndpointAddress.ip("169.254.6.7", Protocol.UDP, 1234))


def test_unknown_service_in_subnet():
    su = Setup()
    net1 = su.system.network("VPN", "169.254.0.0/16")
    dev1 = su.system.device().in_networks(net1, su.system.network()).ip("192.168.4.5")
    ser1_1 = dev1 / TCP(8686).in_network(net1)
    system = su.get_system()

    # the known service with envelope address
    addr = AddressEnvelope(
        address=IPAddress.new("192.168.4.5"),
        content=EndpointAddress.ip("169.254.6.7", Protocol.TCP, 8686))
    s0 = system.get_endpoint(addr)
    assert s0 == ser1_1.entity
    assert s0.get_parent_host() == dev1.entity

    # right host, but service in different subnet
    addr = EndpointAddress.ip("192.168.4.5", Protocol.TCP, 8686)
    s0 = system.get_endpoint(addr)
    assert s0 != ser1_1.entity

    # address like in subnet, but actully for host
    assert s0.get_parent_host() == dev1.entity
    addr = EndpointAddress.ip("169.254.6.7", Protocol.TCP, 8686)
    s0 = system.get_endpoint(addr)
    assert s0.get_parent_host() != dev1.entity
