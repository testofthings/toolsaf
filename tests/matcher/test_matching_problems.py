"""Test broadcast matching"""

from toolsaf.builder_backend import SystemBackend
from toolsaf.common.address import IPAddress
from toolsaf.common.basics import Status
from toolsaf.common.traffic import IPFlow
from toolsaf.core.matcher import SystemMatcher
from toolsaf.main import ARP, UDP

def test_broadcast_matching_with_arp():
    sb = SystemBackend()
    any_host = sb.any()
    dev1 = sb.device("Dev1").ip("10.42.0.184")
    dev2 = sb.device("Dev2").ip("10.42.0.200")
    dev2_bc = dev2.broadcast(UDP(port=6667))
    c0 = dev1 >> dev2_bc
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
