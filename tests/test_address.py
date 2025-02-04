from typing import Optional
from ipaddress import IPv4Network
from toolsaf.common.address import (
    Addresses, DNSName, EndpointAddress, EntityTag, HWAddress, HWAddresses,
    IPAddress, IPAddresses, Network, Protocol, AddressSequence, AddressSegment, AnyAddress
)
from toolsaf.common.traffic import Protocol
from toolsaf.main import HTTP, TCP
from tests.test_model import Setup


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


def _segment(address: AnyAddress, segment_type: Optional[str]=None) -> AddressSegment:
    return AddressSegment(address, segment_type)


def test_address_sequence():
    addr1 = EntityTag.new("Test1")
    addr2 = EndpointAddress(EntityTag("Test2"), Protocol.TCP, 80)
    seq = AddressSequence.new(addr1, addr2)
    assert seq.segments == [_segment(addr1), _segment(addr2)]


def test_address_sequence_get_parseable_value():
    addr1 = _segment(EntityTag.new("Test1"))
    addr2 = _segment(EndpointAddress(EntityTag("Test2"), Protocol.TCP, 80))
    addr3 = _segment(EntityTag("Test_SW"), segment_type="software")

    assert AddressSequence([addr1]).get_parseable_value() == "Test1"
    assert AddressSequence([addr2]).get_parseable_value() == "Test2/tcp:80"
    assert AddressSequence([addr1, addr2, addr3]).get_parseable_value() == "Test1&Test2/tcp:80&software=Test_SW"

    addr2.segment_type = "source"
    addr4 = _segment(EndpointAddress(EntityTag("Test4"), Protocol.UDP, 123), segment_type="target")
    assert AddressSequence([addr2, addr4]).get_parseable_value() == \
        "source=Test2/tcp:80&target=Test4/udp:123"


def test_get_system_address():
    system = Setup().system
    system.system.name = "Test System"
    device = system.device("D")

    # IoTSystem
    assert system.system.get_system_address() == AddressSequence([
        _segment(EntityTag("Test System"), segment_type="system")
    ])

    # Host
    assert device.entity.get_system_address() == AddressSequence.new(
        EntityTag.new("D")
    )

    # Service
    service = (device / HTTP).entity
    assert service.get_system_address() == AddressSequence.new(
        EntityTag("D"), EndpointAddress(Addresses.ANY, Protocol.TCP, 80)
    )

    # NodeComponent
    software = device.software("SW").get_software()
    assert software.get_system_address() == AddressSequence([
        _segment(EntityTag("D")), _segment(EntityTag("SW"), segment_type="software")
    ])

    # Connection
    backend = system.backend("B")
    connection = (device >> backend / HTTP).connection
    assert connection.get_system_address() == AddressSequence([
        _segment(EntityTag("D"), "source"),
        _segment(EntityTag("B"), "target"), _segment(EndpointAddress(Addresses.ANY, Protocol.TCP, 80)),
    ])

    connection = ((device / HTTP) >> backend / TCP(port=111)).connection
    assert connection.get_system_address() == AddressSequence([
        _segment(EntityTag("D"), "source"), _segment(EndpointAddress(Addresses.ANY, Protocol.TCP, 80)),
        _segment(EntityTag("B"), "target"), _segment(EndpointAddress(Addresses.ANY, Protocol.TCP, 111)),
    ])


def test_parse_system_address():
    assert Addresses.parse_system_address(
        "1.2.3.4"
    ) == AddressSequence.new(IPAddress.new("1.2.3.4"))

    assert Addresses.parse_system_address(
        "1:2:3:4:5:6|hw"
    ) == AddressSequence.new(HWAddress.new("1:2:3:4:5:6"))

    assert Addresses.parse_system_address(
        "Test_Device"
    ) == AddressSequence.new(EntityTag("Test_Device"))

    assert Addresses.parse_system_address(
        "1.2.3.4/udp:1234"
    ) == AddressSequence.new(EndpointAddress(IPAddress.new("1.2.3.4"), Protocol.UDP, 1234))

    assert Addresses.parse_system_address(
        "Test_Device/tcp:80"
    ) == AddressSequence.new(EndpointAddress(EntityTag("Test_Device"), Protocol.TCP, 80))

    assert Addresses.parse_system_address(
        "ff_ff_ff_ff_ff_ff/arp"
    ) == AddressSequence.new(EndpointAddress(EntityTag("ff_ff_ff_ff_ff_ff"), Protocol.ARP))

    assert Addresses.parse_system_address(
        "Test_Device&software=Test_SW"
    ) == AddressSequence([
        _segment(EntityTag("Test_Device")), _segment(EntityTag("Test_SW"), "software")
    ])

    assert Addresses.parse_system_address(
        "source=Test_Device&target=Test_Device/tcp:80"
    ) == AddressSequence([
        _segment(EntityTag("Test_Device"), "source"), _segment(EndpointAddress(EntityTag("Test_Device"), Protocol.TCP, 80), "target")
    ])

    assert Addresses.parse_system_address(
        "source=Test_Device/udp:123&target=Test_Device"
    ) == AddressSequence([
        _segment(EndpointAddress(EntityTag("Test_Device"), Protocol.UDP, 123), "source"), _segment(EntityTag("Test_Device"), "target")
    ])

    assert Addresses.parse_system_address(
        "source=Test_Device/tcp:80&target=Test_Device/udp:123"
    ) == AddressSequence([
        _segment(EndpointAddress(EntityTag("Test_Device"), Protocol.TCP, 80), "source"),
        _segment(EndpointAddress(EntityTag("Test_Device"), Protocol.UDP, 123), "target")
    ])

    assert Addresses.parse_system_address(
        "source=1.2.3.4&target=Test_Device/tcp:80"
    ) == AddressSequence([
        _segment(IPAddress.new("1.2.3.4"), "source"), _segment(EndpointAddress(EntityTag("Test_Device"), Protocol.TCP, 80), "target")
    ])

    assert Addresses.parse_system_address(
        "source=1.2.3.4/tcp:80&target=01:01:01:01:01:01|hw/tcp:80"
    ) == AddressSequence([
        _segment(EndpointAddress(IPAddress.new("1.2.3.4"), Protocol.TCP, 80), "source"),
        _segment(EndpointAddress(HWAddress.new("01:01:01:01:01:01"), Protocol.TCP, 80), "target")
    ])

    assert Addresses.parse_system_address(
        "Test_Device/tcp:80&software=Test_SW"
    ) == AddressSequence([
        _segment(EndpointAddress(EntityTag("Test_Device"), Protocol.TCP, 80)), _segment(EntityTag("Test_SW"), "software")
    ])

    assert Addresses.parse_system_address(
        "Test/tcp:80&software=VM&VirtualEnv/udp:123"
    ) == AddressSequence([
        _segment(EndpointAddress(EntityTag("Test"), Protocol.TCP, 80)),
        _segment(EntityTag("VM"), "software"),
        _segment(EndpointAddress(EntityTag("VirtualEnv"), Protocol.UDP, 123))
    ])


def test_system_endpoint_address():
    # Endpoint address with host
    ep = AddressSequence.new(EndpointAddress(EntityTag("Device"), Protocol.TCP, 1234))
    # Endpoint address ANY host, as it is used in services
    ep_any = AddressSequence.new(EntityTag("Device"), EndpointAddress(Addresses.ANY, Protocol.TCP, 1234))
    # Explicit endpoint address for a service
    ep_exp = AddressSequence.new(EntityTag("Device"), EndpointAddress(IPAddresses.BROADCAST, Protocol.TCP, 1234))

    ep_s = ep.get_parseable_value()
    ep_any_s = ep_any.get_parseable_value()
    ep_exp_s = ep_exp.get_parseable_value()
    assert ep_s == "Device/tcp:1234"
    assert ep_any_s == "Device/tcp:1234"
    assert ep_exp_s == "Device&255.255.255.255/tcp:1234"

    ep2 = Addresses.parse_system_address(ep_s)
    ep_any2 = Addresses.parse_system_address(ep_any_s)
    ep_exp2 = Addresses.parse_system_address(ep_exp_s)
    assert ep2 == ep
    assert ep_any2 == ep  # Parses into same as ep!
    assert ep_exp2 == ep_exp2


def test_system_endpoint_address_no_protocol():
    ep = AddressSequence.new(EntityTag("Device"), EndpointAddress(Addresses.ANY, Protocol.ETHERNET))
    ep_str = ep.get_parseable_value()
    assert ep_str == "Device/eth"
    # parsed into one entity tag
    ep2 = Addresses.parse_system_address(ep_str)
    assert [s.address for s in ep2.segments] == [EndpointAddress(EntityTag("Device"), Protocol.ETHERNET)]
