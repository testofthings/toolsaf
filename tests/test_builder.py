from tcsfw.address import IPAddress
from tcsfw.main import SystemBuilder, UDP, HTTP
from tcsfw.verdict import Verdict


def test_just_host():
    sb = SystemBuilder()
    dev = sb.device()
    assert dev.entity.status.verdict == Verdict.NOT_SEEN


def test_hosts():
    sb = SystemBuilder()
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

    assert dev1.entity.status.verdict == Verdict.NOT_SEEN
    assert dev2.entity.status.verdict == Verdict.NOT_SEEN
    assert dev3.entity.status.verdict == Verdict.NOT_SEEN

    # used port
    assert (dev2 / UDP(port=1234)).entity.status.verdict == Verdict.NOT_SEEN
    # unused port
    assert (dev3 / HTTP).entity.status.verdict == Verdict.NOT_SEEN


def test_address():
    assert not IPAddress.new("1.0.0.1").is_multicast()

