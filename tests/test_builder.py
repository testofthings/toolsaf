import pytest

from toolsaf.common.address import IPAddress
from toolsaf.builder_backend import SystemBackend
from toolsaf.main import UDP, HTTP, ConfigurationException
from toolsaf.common.basics import Status


def test_just_host():
    sb = SystemBackend()
    dev = sb.device()
    assert dev.entity.status == Status.EXPECTED


def test_hosts():
    sb = SystemBackend()
    dev1 = sb.device()
    dev2 = sb.device()
    dev3 = sb.device()
    c1 = dev1 >> dev2 / UDP(port=1234)
    dev3 / HTTP

    assert dev1.entity.name == "Device 1"
    assert dev2.entity.name == "Device 2"
    assert dev3.entity.name == "Device 3"

    assert c1.connection.source == dev1.entity
    assert c1.connection.target == (dev2 / UDP(port=1234)).entity

    assert dev1.entity.status == Status.EXPECTED
    assert dev2.entity.status == Status.EXPECTED
    assert dev3.entity.status == Status.EXPECTED

    # used port
    assert (dev2 / UDP(port=1234)).entity.status == Status.EXPECTED
    # unused port
    assert (dev3 / HTTP).entity.status == Status.EXPECTED


def test_address():
    assert not IPAddress.new("1.0.0.1").is_multicast()



def test_networks():
    sb = SystemBackend()
    default = sb.network().network
    assert default is sb.system.get_default_network()
    assert default.name == "default"
    assert [str(n) for n in default.ip_network] == ["192.168.0.0/16"]

    subnet = sb.network("VPN", ip_mask="169.254.0.0/16").network
    assert subnet.name == "VPN"
    assert [str(n) for n in subnet.ip_network] == ["169.254.0.0/16"]

    # A subnet without a mask covers no IP addresses
    assert sb.network("Unknown").network.ip_network == []

    # The mask is normalized
    assert [str(n) for n in sb.network("Sub", ip_mask="10.0.0.0/255.0.0.0").network.ip_network] == ["10.0.0.0/8"]
    assert [str(n) for n in sb.network("Sub2", ip_mask=" 10.1.0.0/16 ").network.ip_network] == ["10.1.0.0/16"]

    # A network can carry both an IPv4 and an IPv6 mask (dual-stack)
    dual = sb.network("Dual", ip_mask="10.2.0.0/16")
    dual.mask("2001:db8::/32")
    assert [str(n) for n in dual.network.ip_network] == ["10.2.0.0/16", "2001:db8::/32"]


def test_mask_replaces_same_ip_version_by_default():
    sb = SystemBackend()
    net = sb.network("Sub", ip_mask="10.0.0.0/16")

    # A new IPv4 mask replaces the old one, an IPv6 mask is added alongside
    net.mask("10.1.0.0/16")
    assert [str(n) for n in net.network.ip_network] == ["10.1.0.0/16"]
    net.mask("2001:db8::/32")
    assert [str(n) for n in net.network.ip_network] == ["10.1.0.0/16", "2001:db8::/32"]
    net.mask("2001:db9::/32")
    assert [str(n) for n in net.network.ip_network] == ["10.1.0.0/16", "2001:db9::/32"]

    # append=True keeps multiple masks of the same IP version
    net.mask("10.2.0.0/16", append=True)
    assert [str(n) for n in net.network.ip_network] == ["10.1.0.0/16", "2001:db9::/32", "10.2.0.0/16"]


def test_loopback_network():
    loopback = SystemBackend().network(ip_mask="127.0.0.0/8").network
    assert loopback.name == "loopback"
    assert [str(n) for n in loopback.ip_network] == ["127.0.0.0/8"]

    loopback = SystemBackend().network("loopback").network
    assert loopback.name == "loopback"
    assert [str(n) for n in loopback.ip_network] == ["127.0.0.0/8"]
    assert loopback.is_local(IPAddress.new("127.0.0.1"))

    assert [str(n) for n in SystemBackend().network("loopback", ip_mask="127.0.0.0/8").network.ip_network] \
        == ["127.0.0.0/8"]

    # The loopback network also recognizes the IPv6 loopback mask, alone or alongside the IPv4 one
    loopback_v6 = SystemBackend().network(ip_mask="::1/128").network
    assert loopback_v6.name == "loopback"
    assert [str(n) for n in loopback_v6.ip_network] == ["::1/128"]
    assert loopback_v6.is_local(IPAddress.new("::1"))

    dual_loopback = SystemBackend().network("loopback", ip_mask="127.0.0.0/8")
    dual_loopback.mask("::1/128")
    assert [str(n) for n in dual_loopback.network.ip_network] == ["127.0.0.0/8", "::1/128"]


def test_loopback_network_errors():
    with pytest.raises(ConfigurationException,
                       match="Loopback network must be named 'loopback', not 'lo'"):
        SystemBackend().network("lo", ip_mask="127.0.0.0/8")

    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8 or ::1/128, got '10.0.0.0/8'"):
        SystemBackend().network("loopback", ip_mask="10.0.0.0/8")

    for name in ["", "loopback", "lo"]:
        with pytest.raises(ConfigurationException,
                           match=r"Loopback network must have IP mask 127.0.0.0/8 or ::1/128, got '127.0.0.0/24'"):
            SystemBackend().network(name, ip_mask="127.0.0.0/24")

    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8 or ::1/128, got '2001:db8::/32'"):
        SystemBackend().network("loopback", ip_mask="2001:db8::/32")

    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8 or ::1/128, got '10.0.0.0/8'"):
        SystemBackend().network(ip_mask="127.0.0.0/8").mask("10.0.0.0/8")
    with pytest.raises(ConfigurationException,
                       match="Loopback network must be named 'loopback', not 'default'"):
        SystemBackend().network().mask("127.0.0.0/8")


def test_bad_network_ip_mask():
    for mask in ["not-a-mask", "10.0.0.0/33", "10.0.0.1/8", "10.0.0.0/8/8"]:
        with pytest.raises(ConfigurationException, match="Bad network IP mask"):
            SystemBackend().network("Sub", ip_mask=mask)

    assert SystemBackend().network("Sub", ip_mask="").network.ip_network == []
