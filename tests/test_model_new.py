from tcsfw.address import DNSName, EntityTag, HWAddress, IPAddress
from tcsfw.basics import Status
from tcsfw.main import SSH
from tcsfw.services import NameEvent
from tcsfw.traffic import NO_EVIDENCE, IPFlow
from tcsfw.verdict import Verdict
from tests.test_model import Setup


class Setup_1(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device().hw("10:0:0:0:0:1")
        self.device2 = self.system.device().name("some.local")
        self.ssh = self.device1 / SSH
        self.ssh_connectoin = self.device2 >> self.ssh


def test_connection_reassignment():
    su = Setup_1()
    i = su.get_inspector()
    system = su.get_system()
    assert len(system.children) == 2

    # connection from unkonwn entiy
    cs = i.connection(IPFlow.TCP("10:0:0:0:0:2", "192.168.0.2", 22004) >> ("10:0:0:0:0:1", "192.168.0.1", 22))
    assert len(system.children) == 3
    assert cs.source.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert cs.source == system.children[2]
    assert cs.target == su.ssh.entity

    # learn address, the connection is actually expected
    i.name(NameEvent(NO_EVIDENCE, service=None, tag=DNSName("some.local"), address=IPAddress.new("192.168.0.2")))
    assert su.device2.entity.addresses == {
        DNSName("some.local"),
        IPAddress.new("192.168.0.2"),
        # HWAddress.new("10:0:0:0:0:2"),
        EntityTag("Device_2")
    }
    # assert cs.source == su.device2.entity

