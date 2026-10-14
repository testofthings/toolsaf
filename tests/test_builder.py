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
    assert (default.name, str(default.ip_network)) == ("default", "192.168.0.0/16")

    subnet = sb.network("VPN", ip_mask="169.254.0.0/16").network
    assert (subnet.name, str(subnet.ip_network)) == ("VPN", "169.254.0.0/16")

    # A subnet without a mask covers no IP addresses
    assert sb.network("Unknown").network.ip_network is None

    # The mask is normalized
    assert str(sb.network("Sub", ip_mask="10.0.0.0/255.0.0.0").network.ip_network) == "10.0.0.0/8"
    assert str(sb.network("Sub2", ip_mask=" 10.1.0.0/16 ").network.ip_network) == "10.1.0.0/16"


def test_loopback_network():
    loopback = SystemBackend().network(ip_mask="127.0.0.0/8").network
    assert (loopback.name, str(loopback.ip_network)) == ("loopback", "127.0.0.0/8")

    loopback = SystemBackend().network("loopback").network
    assert (loopback.name, str(loopback.ip_network)) == ("loopback", "127.0.0.0/8")
    assert loopback.is_local(IPAddress.new("127.0.0.1"))

    assert str(SystemBackend().network("loopback", ip_mask="127.0.0.0/8").network.ip_network) \
        == "127.0.0.0/8"


def test_loopback_network_errors():
    with pytest.raises(ConfigurationException,
                       match="Loopback network must be named 'loopback', not 'lo'"):
        SystemBackend().network("lo", ip_mask="127.0.0.0/8")

    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8, got '10.0.0.0/8'"):
        SystemBackend().network("loopback", ip_mask="10.0.0.0/8")

    for name in ["", "loopback", "lo"]:
        with pytest.raises(ConfigurationException,
                           match=r"Loopback network must have IP mask 127.0.0.0/8, got '127.0.0.0/24'"):
            SystemBackend().network(name, ip_mask="127.0.0.0/24")

    with pytest.raises(ConfigurationException,
                       match=r"Loopback network must have IP mask 127.0.0.0/8, got '::1/128'"):
        SystemBackend().network(ip_mask="::1/128")

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

    assert SystemBackend().network("Sub", ip_mask="").network.ip_network is None


def test_host_tag_conflict():
    sb = SystemBackend()
    sb.device("A B")
    changes = set(sb._changes)
    with pytest.raises(ConfigurationException, match="Host name 'A_B' conflicts with system address 'A_B' of host 'A B'"):
        sb.device("A_B")
    assert sb._changes.keys() == changes  # failed call did not record changes
    assert len(sb.system.get_hosts()) == 1
    assert sb.device("A B") is sb.hosts_by_name["A B"]  # same name is fine, it is the same host


def test_host_tag_conflict_after_numbering():
    sb = SystemBackend()
    sb.device()
    sb.device()  # first host renamed 'Device 1', but its tag remains 'Device'
    assert [(h.name, str(h.get_system_address())) for h in sb.system.get_hosts()] == [
        ("Device 1", "Device"), ("Device 2", "Device_2")]
    sb.device()
    with pytest.raises(ConfigurationException, match="conflicts with system address 'Device' of host 'Device 1'"):
        sb.device("Device")


def test_free_name_after_rename():
    sb = SystemBackend()
    first = sb.device()
    first.name("Test")  # tag Device remains
    second = sb.device()
    third = sb.device()
    assert [(h.name, str(h.get_system_address())) for h in sb.system.get_hosts()] == [
        ("Test", "Device"), ("Device 1", "Device_1"), ("Device 2", "Device_2")]
    assert first.entity is not second.entity
    assert sb.device("Device 1") is second and sb.device("Device 2") is third
    sb.system.check_unique_system_addresses()
