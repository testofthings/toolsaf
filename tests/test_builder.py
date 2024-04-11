from tcsfw.address import IPAddress
from tcsfw.verdict import Verdict
from tcsfw.builder_backend import SystemBackend
from tcsfw.main import UDP, HTTP
from tcsfw.basics import Status


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

