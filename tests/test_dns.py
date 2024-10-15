import pathlib

from tdsaf.core.address import EntityTag, IPAddress, DNSName, Protocol
from tdsaf.core.verdict import Verdict
from tdsaf.builder_backend import SystemBackend
from tdsaf.inspector import Inspector
from tdsaf.main import DNS
from tdsaf.matcher import SystemMatcher
from tdsaf.adapters.pcap_reader import PCAPReader
from tdsaf.core.traffic import IPFlow
from tdsaf.core.basics import Status


def test_dns():
    sb = SystemBackend()
    dev1 = sb.device().ip("1.0.0.1")
    dns = sb.backend().ip("5.5.5.5") / DNS
    c1 = dev1 >> dns
    m = SystemMatcher(sb.system)

    assert sb.system.message_listeners[dns.entity] == Protocol.DNS
    f1 = m.connection(IPFlow.UDP("1:0:0:0:0:1", "1.0.0.1", 4321) >> ("5:0:0:0:0:5", "5.5.5.5", 53))
    sb.system.learn_named_address(DNSName("name1.local"), IPAddress.new("1.0.0.1"))

    assert f1 == c1.connection
    assert dev1.entity.addresses == {EntityTag("Device"), IPAddress.new("1.0.0.1"), DNSName("name1.local")}


def test_dns_pcap():
    sb = SystemBackend()
    dev1 = sb.device().ip("192.168.20.132")
    dns = sb.backend().ip("155.198.142.7") / DNS
    c1 = dev1 >> dns
    m = Inspector(sb.system)

    s = sb.system
    PCAPReader.inspect(pathlib.Path("tests/samples/pcap/dns.pcap"), m)
    hosts = s.get_hosts()
    assert len(hosts) == 10

    host = s.get_endpoint(DNSName("latinum.amazon.com"))
    assert host.addresses == {DNSName("latinum.amazon.com"), IPAddress.new("54.239.21.157")}
    assert host.name == "latinum.amazon.com"
    assert host.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)

    host = s.get_endpoint(DNSName("ns-923.amazon.com"))
    assert host.addresses == {DNSName("ns-923.amazon.com"), IPAddress.new("52.86.96.73")}
    assert host.name == "ns-923.amazon.com"
    assert host.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)

    c = m.connection(IPFlow.udp_flow(source_ip="192.168.20.132", target_ip="155.198.142.7", target_port=53))
    assert c.get_expected_verdict() == Verdict.PASS


def test_dns_large_pcap():
    sb = SystemBackend()
    sb.any() / DNS
    m = Inspector(sb.system)
    s = sb.system
    PCAPReader.inspect(pathlib.Path("tests/samples/pcap/dns-large-set.pcap"), m)
    hosts = sorted(s.get_hosts(), key=lambda h: -len(h.addresses))
    assert len(hosts) == 85
    h = hosts[0]
    assert h.name == "gateway.fe.apple-dns.net"
    assert len(h.addresses) == 58
    hs = set([h.name for h in hosts])
    assert "_dns.resolver.arpa" in hs


def test_dns_large_pcap2():
    sb = SystemBackend()
    sb.any() / DNS
    m = Inspector(sb.system)
    s = sb.system
    PCAPReader.inspect(pathlib.Path("tests/samples/pcap/dns-large-set2.pcap"), m)
    hosts = sorted(s.get_hosts(), key=lambda h: -len(h.addresses))
    assert len(hosts) == 18
    hs = set([h.name for h in hosts])
    assert "10.10.0.1" in hs
    assert "1.0.17.172" in hs
    assert "fe80::b52e:fb6c:dd94:7767" in hs
    assert "play.google.com" in hs

