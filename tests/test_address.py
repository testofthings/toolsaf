from ipaddress import IPv4Network
from toolsaf.common.address import Addresses, DNSName, EndpointAddress, EntityTag, HWAddress, HWAddresses, IPAddress, IPAddresses, Network, Protocol


def test_hw_address():
    ad = HWAddress("00:11:22:33:44:55")
    assert f"{ad}" == "00:11:22:33:44:55"
    assert ad.get_parseable_value() == "00:11:22:33:44:55|hw"
    assert ad.is_null() is False
    assert ad.is_global() is False
    assert ad == HWAddress.new("00:11:22:33:44:55")
    assert ad == HWAddress.new("0:11:22:33:44:55")

    assert HWAddresses.NULL == HWAddress.new("00:00:00:00:00:00")
    assert HWAddresses.NULL.is_null() is True


def test_ip_address():
    ad = IPAddress.new("1.2.3.4")
    assert f"{ad}" == "1.2.3.4"
    assert ad.get_parseable_value() == "1.2.3.4"
    assert ad.is_null() is False
    assert ad.is_global() is True

    assert IPAddress.new("0.0.0.0") == IPAddresses.NULL
    assert IPAddresses.NULL.is_null() is True
    assert IPAddresses.NULL.is_global() is False

    assert IPAddress.new("192.168.1.1").is_global() is False


def test_dns_name():
    ad = DNSName("www.example.com")
    assert f"{ad}" == "www.example.com"
    assert ad.get_parseable_value() == "www.example.com|name"
    assert ad.is_null() is False
    assert ad.is_global() is True
    assert ad == DNSName("www.example.com")
    assert ad != DNSName("www.example.org")


def test_endpoint_address():
    ad = EndpointAddress.ip("1.2.3.4", Protocol.UDP, 1234)
    assert f"{ad}" == "1.2.3.4/udp:1234"
    assert ad.get_parseable_value() == "1.2.3.4/udp:1234"
    assert ad.get_host() == IPAddress.new("1.2.3.4")
    assert ad.protocol == Protocol.UDP
    assert ad.port == 1234

    ad = EndpointAddress.hw("0:1:2:3:4:5", Protocol.UDP, 1234)
    assert f"{ad}" == "00:01:02:03:04:05/udp:1234"
    assert ad.get_parseable_value() == "00:01:02:03:04:05|hw/udp:1234"


def test_parse_address():
    a = Addresses.parse_address("1.2.3.4")
    assert isinstance(a, IPAddress)
    assert f"{a}" == "1.2.3.4"

    a = Addresses.parse_address("www.example.com|name")
    assert isinstance(a, DNSName)
    assert f"{a}" == "www.example.com"

    a = Addresses.parse_address("1:2:3:4:5:6|hw")
    assert isinstance(a, HWAddress)
    assert f"{a}" == "01:02:03:04:05:06"


def test_parse_endpoint_address():
    a = Addresses.parse_endpoint("1.2.3.4/udp:1234")
    assert isinstance(a, EndpointAddress)
    assert f"{a}" == "1.2.3.4/udp:1234"
    assert a.get_host() == IPAddress.new("1.2.3.4")
    assert a.protocol == Protocol.UDP
    assert a.port == 1234

    a = Addresses.parse_endpoint("1:2:3:4:5:6|hw/HTTP")
    assert f"{a}" == "01:02:03:04:05:06/http"
    assert a.get_host() == HWAddress.new("01:02:03:04:05:06")
    assert a.protocol == Protocol.HTTP
    assert a.port == -1

    ad = EndpointAddress(EntityTag.new("xxx"), Protocol.ETHERNET, 35000)
    assert f"{ad}" == "xxx/eth:35000"
    ad2 = Addresses.parse_endpoint(ad.get_parseable_value())
    assert ad == ad2


def test_hw_address_generation():
    ip = IPAddress.new("192.168.0.2")
    hw = HWAddress.from_ip(ip)
    assert hw == HWAddress('40:00:c0:a8:00:02')


def test_ip_network_matching():
    nw = Network("net", ip_network=IPv4Network("22.33.0.0/16"))
    assert not nw.is_local(IPAddress.new("22.2.3.4"))
    assert nw.is_local(IPAddress.new("22.33.3.4"))
    assert nw.is_local(IPAddress.new("22.33.33.4"))

    nw = Network("net", ip_network=IPv4Network("0.0.0.0/0"))
    assert nw.is_local(IPAddress.new("22.33.3.4"))
    assert nw.is_local(IPAddress.new("22.2.3.4"))
    assert nw.is_local(IPAddress.new("22.33.3.4"))
    assert nw.is_local(IPAddress.new("22.33.33.4"))
