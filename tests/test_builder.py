import pytest

from toolsaf.common.address import IPAddress
from toolsaf.common.verdict import Verdict
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
    assert (default.name, str(default.ip_network)) == ("default", "192.168.0.0/16")

    subnet = sb.network("VPN", ip_mask="169.254.0.0/16").network
    assert (subnet.name, str(subnet.ip_network)) == ("VPN", "169.254.0.0/16")

    # A subnet without a mask covers no IP addresses
    assert sb.network("Unknown").network.ip_network is None

    # The mask is normalized
    assert str(sb.network("Sub", ip_mask="10.0.0.0/255.0.0.0").network.ip_network) == "10.0.0.0/8"
    assert str(sb.network("Sub2", ip_mask=" 10.1.0.0/16 ").network.ip_network) == "10.1.0.0/16"


def test_loopback_network():
    # The well-known IP mask gives the well-known name...
    loopback = SystemBackend().network(ip_mask="127.0.0.0/8").network
    assert (loopback.name, str(loopback.ip_network)) == ("loopback", "127.0.0.0/8")

    # ...and the well-known name gives the well-known IP mask
    loopback = SystemBackend().network("loopback").network
    assert (loopback.name, str(loopback.ip_network)) == ("loopback", "127.0.0.0/8")
    assert loopback.is_local(IPAddress.new("127.0.0.1"))

    # Both can be given
    assert str(SystemBackend().network("loopback", ip_mask="127.0.0.0/8").network.ip_network) \
        == "127.0.0.0/8"


def test_loopback_network_errors():
    # A loopback mask requires the well-known name
    with pytest.raises(ConfigurationException,
                       match="Loopback network must be named 'loopback', not 'lo'"):
        SystemBackend().network("lo", ip_mask="127.0.0.0/8")

    # The well-known name requires the loopback mask
    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8, got '10.0.0.0/8'"):
        SystemBackend().network("loopback", ip_mask="10.0.0.0/8")

    # Only the well-known loopback mask is accepted, whatever the network is named
    for name in ["", "loopback", "lo"]:
        with pytest.raises(ConfigurationException,
                           match=r"Loopback network must have IP mask 127.0.0.0/8, got '127.0.0.0/24'"):
            SystemBackend().network(name, ip_mask="127.0.0.0/24")

    # IPv6 is not supported, not even for loopback
    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8, got '::1/128'"):
        SystemBackend().network(ip_mask="::1/128")

    # The rules are not bypassed by setting the mask afterwards
    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8, got '10.0.0.0/8'"):
        SystemBackend().network(ip_mask="127.0.0.0/8").mask("10.0.0.0/8")
    with pytest.raises(ConfigurationException,
                       match="Loopback network must be named 'loopback', not 'default'"):
        SystemBackend().network().mask("127.0.0.0/8")


def test_bad_network_ip_mask():
    for mask in ["not-a-mask", "10.0.0.0/33", "10.0.0.1/8", "10.0.0.0/8/8"]:
        with pytest.raises(ConfigurationException, match="Bad network IP mask"):
            SystemBackend().network("Sub", ip_mask=mask)

    # An empty mask is the same as no mask at all
    assert SystemBackend().network("Sub", ip_mask="").network.ip_network is None
