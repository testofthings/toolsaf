"""Test broadcast matching"""

from toolsaf.builder_backend import SystemBackend
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

