"""Test broadcast matching"""

from toolsaf.builder_backend import SystemBackend
from toolsaf.common.address import IPAddress
from toolsaf.common.basics import Status
from toolsaf.common.traffic import Evidence, IPFlow
from toolsaf.core.inspector import Inspector
from toolsaf.core.matcher import SystemMatcher
from toolsaf.core.model import EvidenceNetworkSource
from toolsaf.main import ARP, UDP

def test_broadcast_matching_with_arp():
    sb = SystemBackend()
    any_host = sb.any()
    dev1 = sb.device("Dev1").ip("10.42.0.184")
    dev2 = sb.device("Dev2").ip("10.42.0.200")
    c0 = dev1 >> dev2 / UDP(port=6667).broadcast()
    m = SystemMatcher(sb.system)

    f1 = m.connection(IPFlow.UDP("7c:f6:66:24:a7:36", "10.42.0.184", 63144) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 6667))
    assert f1 == c0.connection

    # ARP adds ff:ff:ff:ff:ff:ff listening
    any_host.serve(ARP)
    m = SystemMatcher(sb.system)
    f2 = m.connection(IPFlow.UDP("7c:f6:66:24:a7:36", "10.42.0.184", 63144) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 6667))
    assert f2 == c0.connection


def test_external_masking_expected():
    sb = SystemBackend()
    any_host = sb.any()
    dev1 = sb.device("Dev1").ip("10.42.0.6")
    service1 = dev1 / UDP(port=2000)
    mob1 = sb.mobile("Mob1")

    # artifially create annoying external connection
    m = SystemMatcher(sb.system)
    engine = m.get_context()
    m0 = engine.new_connection(
        (mob1.entity, IPAddress.new("10.42.0.10")),
        (any_host.entity, IPAddress.new("10.42.0.1")),
    )

    # it should not mask Mob1 -> Dev1:2000
    f2 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "10.42.0.10", 22222) >> ("1:0:0:0:0:2", "10.42.0.6", 2000))
    assert f2.source != mob1.entity
    assert f2.target == service1.entity
    assert f2.status == Status.EXTERNAL


def test_broadcast_ip_address_matching():
    """Match unexpected broadcast IP address connections properly"""
    sb = SystemBackend()
    dev1 = sb.device().ip("10.0.0.1")
    system = sb.system
    m = Inspector(system)

    # Assertion below fails before we moved detection of broadcast address to use
    # HW address and not IP address (MatchingContext.new_endpoint)
    # - Detecting broadcast IP address depends on netmask, which the logic currenty does not know
    # - Without detecting the broadcast, the unexpedcted connection endpoint is created with
    #   target address ff:ff:ff:ff:ff:Ff
    # - However, this HW address is not properly matches on subsequent time, leading creation
    #   of another unexpected connection -> assertion fails

    flow = IPFlow.UDP("8:0:0:0:0:1", "10.0.0.1", 2001) >> ("ff:ff:ff:ff:ff:ff", "192.168.255.255", 30000)
    c1 = m.connection(flow)

    flow = IPFlow.UDP("8:0:0:0:0:1", "10.0.0.1", 2002) >> ("ff:ff:ff:ff:ff:ff", "192.168.255.255", 30003)
    c2 = m.connection(flow)

    assert c2 == c1


def test_same_unexpected_connection_many_sources():
    """The same unexpected connection is seen in many sources"""
    sb = SystemBackend()
    dev1 = sb.device().ip("10.0.0.1")
    system = sb.system
    m = Inspector(system)

    conn = None
    for round in [1, 2]:
        flow = IPFlow.UDP("8:0:0:0:0:1", "10.0.0.1", 2000 + round) >> ("8:0:0:0:0:2", "10.0.0.2", 30000)
        flow.evidence = Evidence(EvidenceNetworkSource("test", label=f"label-{round}"))
        c = m.connection(flow) or conn
        assert conn is None or conn == c, "Many unexpected connections created"
        conn = c

    conn = None
    for round in [1, 2, 3]:
        flow = IPFlow.UDP("8:0:0:0:0:1", "10.0.0.1", 20002) >> ("8:0:0:0:0:2", f"11.0.0.{round}", 30000)
        flow.evidence = Evidence(EvidenceNetworkSource("test", label=f"label-{round}"))
        c = m.connection(flow) or conn
        assert conn != c, "Expected all connections different"
        conn = c

    # special case -
