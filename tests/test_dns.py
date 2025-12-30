import pathlib

from toolsaf.common.address import EntityTag, IPAddress, DNSName, Protocol
from toolsaf.common.verdict import Verdict
from toolsaf.builder_backend import SystemBackend
from toolsaf.core.inspector import Inspector
from toolsaf.main import DNS
from toolsaf.core.matcher import SystemMatcher
from toolsaf.adapters.pcap_reader import PCAPReader
from toolsaf.common.traffic import IPFlow
from toolsaf.common.basics import Status


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

    d = {}
    for host in hosts:
        d[host.name] = sorted(str(a) for a in host.addresses)

    assert d == {
        "gateway.fe.apple-dns.net": [
            "17.250.84.10",
            "17.250.84.11",
            "17.250.84.12",
            "17.250.84.13",
            "17.250.84.14",
            "17.250.84.15",
            "17.250.84.16",
            "17.250.84.17",
            "17.250.84.19",
            "17.250.84.2",
            "17.250.84.20",
            "17.250.84.21",
            "17.250.84.22",
            "17.250.84.23",
            "17.250.84.3",
            "17.250.84.34",
            "17.250.84.35",
            "17.250.84.36",
            "17.250.84.37",
            "17.250.84.38",
            "17.250.84.39",
            "17.250.84.4",
            "17.250.84.40",
            "17.250.84.41",
            "17.250.84.42",
            "17.250.84.43",
            "17.250.84.44",
            "17.250.84.46",
            "17.250.84.47",
            "17.250.84.48",
            "17.250.84.49",
            "17.250.84.5",
            "17.250.84.50",
            "17.250.84.51",
            "17.250.84.52",
            "17.250.84.53",
            "17.250.84.54",
            "17.250.84.55",
            "17.250.84.6",
            "17.250.84.66",
            "17.250.84.67",
            "17.250.84.68",
            "17.250.84.69",
            "17.250.84.7",
            "17.250.84.70",
            "17.250.84.71",
            "17.250.84.72",
            "17.250.84.73",
            "17.250.84.74",
            "17.250.84.75",
            "17.250.84.76",
            "17.250.84.77",
            "17.250.84.78",
            "17.250.84.79",
            "17.250.84.8",
            "17.250.84.80",
            "17.250.84.81",
            "17.250.84.82",
            "17.250.84.83",
            "17.250.84.84",
            "17.250.84.85",
            "17.250.84.9",
            "content.fe.apple-dns.net",
            "edge-131.sesto4.ce.apple-dns.net",
            "fmfmobile.fe.apple-dns.net",
            "fmip.fe.apple-dns.net",
            "gateway.fe.apple-dns.net",
            "weather-edge.fe.apple-dns.net"
        ],
        "caldav.fe.apple-dns.net": [
            "17.250.84.18",
            "17.250.84.45",
            "caldav.fe.apple-dns.net",
            "contacts.fe.apple-dns.net"
        ],
        "a2047.dscapi9.akamai.net": [
            "23.73.4.213",
            "23.73.4.215",
            "23.73.4.216",
            "23.73.4.217",
            "23.73.4.218",
            "23.73.4.219",
            "23.73.4.220",
            "23.73.4.221",
            "23.73.4.223",
            "a2047.dscapi9.akamai.net"
        ],
        "init.push-apple.com.akadns.net": [
            "17.188.168.161",
            "17.188.170.135",
            "17.188.170.72",
            "17.188.171.138",
            "17.188.171.202",
            "17.188.171.74",
            "17.188.172.10",
            "17.188.172.72",
            "init.push-apple.com.akadns.net"
        ],
        "network.ruuvi.com": [
            "18.196.5.177",
            "3.66.3.62",
            "3.69.63.236",
            "35.157.172.142",
            "52.57.149.162",
            "54.93.185.169",
            "network.ruuvi.com"
        ],
        "eu-north-courier-4.push-apple.com.akadns.net": [
            "17.57.146.132",
            "17.57.146.133",
            "17.57.146.136",
            "17.57.146.140",
            "17.57.146.141",
            "17.57.146.142",
            "eu-north-courier-4.push-apple.com.akadns.net"
        ],
        "ocsp2.g.aaplimg.com": [
            "17.253.39.201",
            "17.253.39.202",
            "17.253.39.203",
            "17.253.39.204",
            "17.253.39.206",
            "cl2.g.aaplimg.com",
            "ocsp2.g.aaplimg.com"
        ],
        "time.google.com": [
            "216.239.35.0",
            "216.239.35.12",
            "216.239.35.4",
            "216.239.35.8",
            "time.google.com"
        ],
        "time.g.aaplimg.com": [
            "17.253.38.125",
            "17.253.38.253",
            "17.253.52.125",
            "17.253.52.253",
            "time.g.aaplimg.com"
        ],
        "a1931.dscgi3.akamai.net": [
            "62.165.155.19",
            "62.165.155.98",
            "62.165.159.10",
            "62.165.159.11",
            "a1931.dscgi3.akamai.net"
        ],
        "me.apple-dns.net": [
            "17.248.214.30",
            "17.248.214.31",
            "17.248.214.32",
            "me.apple-dns.net"
        ],
        "cl2.apple.com.c.footprint.net": [
            "67.27.205.122",
            "8.238.112.122",
            "8.238.112.250",
            "cl2.apple.com.c.footprint.net"
        ],
        "get-bx.g.aaplimg.com": [
            "17.253.39.207",
            "17.253.39.208",
            "get-bx.g.aaplimg.com"
        ],
        "a1818.dscw154.akamai.net": [
            "62.165.155.41",
            "62.165.155.91",
            "a1818.dscw154.akamai.net"
        ],
        "musicstatus-eu.edge-itunes-apple.com.akadns.net": [
            "17.188.3.12",
            "17.188.3.25",
            "musicstatus-eu.edge-itunes-apple.com.akadns.net"
        ],
        "aidc.origin-apple.com.akadns.net": [
            "17.32.194.12",
            "17.32.194.43",
            "aidc.origin-apple.com.akadns.net"
        ],
        "mr-mailws.icloud.com.akadns.net": [
            "17.57.152.16",
            "17.57.152.21",
            "mr-mailws.icloud.com.akadns.net"
        ],
        "api.github.com": [
            "140.82.121.6",
            "api.github.com"
        ],
        "fp2e7a.wpc.phicdn.net": [
            "192.229.221.95",
            "fp2e7a.wpc.phicdn.net"
        ],
        "e673.dsce9.akamaiedge.net": [
            "23.72.244.23",
            "e673.dsce9.akamaiedge.net"
        ],
        "e10499.dsce9.akamaiedge.net": [
            "23.72.245.63",
            "e10499.dsce9.akamaiedge.net"
        ],
        "imap.mail.me.com.akadns.net": [
            "17.56.9.23",
            "imap.mail.me.com.akadns.net"
        ],
        "kt-prod.v.aaplimg.com": [
            "17.138.175.254",
            "kt-prod.v.aaplimg.com"
        ],
        "Environment": [
            "Environment"
        ],
        "30:c6:f7:52:db:5c": [
            "30:c6:f7:52:db:5c"
        ],
        "c2:77:15:ab:b5:b0": [
            "c2:77:15:ab:b5:b0"
        ],
        "p60-caldav.icloud.com": [
            "p60-caldav.icloud.com"
        ],
        "p60-contacts.icloud.com": [
            "p60-contacts.icloud.com"
        ],
        "p59-contacts.icloud.com": [
            "p59-contacts.icloud.com"
        ],
        "time.apple.com": [
            "time.apple.com"
        ],
        "13-courier.push.apple.com": [
            "13-courier.push.apple.com"
        ],
        "41-courier.push.apple.com": [
            "41-courier.push.apple.com"
        ],
        "18-courier.push.apple.com": [
            "18-courier.push.apple.com"
        ],
        "_dns.resolver.arpa": [
            "_dns.resolver.arpa"
        ],
        "edge-131.sesto4.icloud-content.com": [
            "edge-131.sesto4.icloud-content.com"
        ],
        "p35-content.icloud.com": [
            "p35-content.icloud.com"
        ],
        "p29-content.icloud.com": [
            "p29-content.icloud.com"
        ],
        "p57-content.icloud.com": [
            "p57-content.icloud.com"
        ],
        "iphone-ld.apple.com": [
            "iphone-ld.apple.com"
        ],
        "weather-edge.apple.com": [
            "weather-edge.apple.com"
        ],
        "gsp-ssl.ls.apple.com": [
            "gsp-ssl.ls.apple.com"
        ],
        "weather-data.apple.com": [
            "weather-data.apple.com"
        ],
        "ocsp.digicert.com": [
            "ocsp.digicert.com"
        ],
        "metrics.icloud.com": [
            "metrics.icloud.com"
        ],
        "42-courier.push.apple.com": [
            "42-courier.push.apple.com"
        ],
        "42.courier-push-apple.com.akadns.net": [
            "42.courier-push-apple.com.akadns.net"
        ],
        "gateway.icloud.com": [
            "gateway.icloud.com"
        ],
        "p60-fmfmobile.icloud.com": [
            "p60-fmfmobile.icloud.com"
        ],
        "gspe79-ssl.ls.apple.com": [
            "gspe79-ssl.ls.apple.com"
        ],
        "45-courier.push.apple.com": [
            "45-courier.push.apple.com"
        ],
        "init.itunes.apple.com": [
            "init.itunes.apple.com"
        ],
        "musicstatus.itunes.apple.com": [
            "musicstatus.itunes.apple.com"
        ],
        "apps.mzstatic.com": [
            "apps.mzstatic.com"
        ],
        "47-courier.push.apple.com": [
            "47-courier.push.apple.com"
        ],
        "configuration.ls.apple.com": [
            "configuration.ls.apple.com"
        ],
        "aidc.apple.com": [
            "aidc.apple.com"
        ],
        "ocsp2.apple.com": [
            "ocsp2.apple.com"
        ],
        "4-courier.push.apple.com": [
            "4-courier.push.apple.com"
        ],
        "iphone-ld.origin-apple.com.akadns.net": [
            "iphone-ld.origin-apple.com.akadns.net"
        ],
        "p72-imap.mail.me.com": [
            "p72-imap.mail.me.com"
        ],
        "p72-mailws.icloud.com": [
            "p72-mailws.icloud.com"
        ],
        "ocsp2-lb.apple.com.akadns.net": [
            "ocsp2-lb.apple.com.akadns.net"
        ],
        "7-courier.push.apple.com": [
            "7-courier.push.apple.com"
        ],
        "4.courier-push-apple.com.akadns.net": [
            "4.courier-push-apple.com.akadns.net"
        ],
        "14-courier.push.apple.com": [
            "14-courier.push.apple.com"
        ],
        "8-courier.push.apple.com": [
            "8-courier.push.apple.com"
        ],
        "init.push.apple.com": [
            "init.push.apple.com"
        ],
        "2-courier.push.apple.com": [
            "2-courier.push.apple.com"
        ],
        "22-courier.push.apple.com": [
            "22-courier.push.apple.com"
        ],
        "8.courier-push-apple.com.akadns.net": [
            "8.courier-push-apple.com.akadns.net"
        ],
        "16-courier.push.apple.com": [
            "16-courier.push.apple.com"
        ],
        "p72-mailws.icloud.com.akadns.net": [
            "p72-mailws.icloud.com.akadns.net"
        ],
        "23-courier.push.apple.com": [
            "23-courier.push.apple.com"
        ],
        "5-courier.push.apple.com": [
            "5-courier.push.apple.com"
        ],
        "p72-imap.mail.me.com.akadns.net": [
            "p72-imap.mail.me.com.akadns.net"
        ],
        "kt-prod.ess.apple.com": [
            "kt-prod.ess.apple.com"
        ],
        "39-courier.push.apple.com": [
            "39-courier.push.apple.com"
        ],
        "21-courier.push.apple.com": [
            "21-courier.push.apple.com"
        ],
        "23.courier-push-apple.com.akadns.net": [
            "23.courier-push-apple.com.akadns.net"
        ],
        "39.courier-push-apple.com.akadns.net": [
            "39.courier-push-apple.com.akadns.net"
        ],
        "27-courier.push.apple.com": [
            "27-courier.push.apple.com"
        ],
        "36-courier.push.apple.com": [
            "36-courier.push.apple.com"
        ],
        "p60-fmip.icloud.com": [
            "p60-fmip.icloud.com"
        ],
        "cl2.apple.com": [
            "cl2.apple.com"
        ],
        "35-courier.push.apple.com": [
            "35-courier.push.apple.com"
        ]
    }

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

