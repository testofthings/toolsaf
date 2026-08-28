import pytest

from toolsaf.common.address import IPAddress
from toolsaf.builder_backend import SystemBackend
from toolsaf.core.matcher import SystemMatcher
from toolsaf.core.model import Connection
from toolsaf.main import ConfigurationException, UDP, HTTP
from toolsaf.common.basics import ExternalActivity, Status
from toolsaf.common.traffic import IPFlow


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


def test_check_system_addresses():
    sb = SystemBackend()
    sb.device().hw("a:0:0:0:0:1").external_activity(ExternalActivity.UNLIMITED)
    m = SystemMatcher(sb.system)

    cs = m.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1100) >> ("a:0:0:0:0:2", "1.0.0.2", 1234))
    assert cs.status == Status.EXTERNAL
    assert not sb.system.get_connections()
    sb._check_system_addresses()

    duplicate = Connection(cs.source, cs.target)
    duplicate.status = Status.EXTERNAL
    cs.source.get_parent_host().connections.append(duplicate)
    with pytest.raises(ConfigurationException, match="does not have a unique system address"):
        sb._check_system_addresses()

