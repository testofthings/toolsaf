"""Test shell command output parsing"""

import pathlib

from tcsfw.address import EntityTag, IPAddress
from tcsfw.basics import ExternalActivity, Status
from tcsfw.batch_import import BatchImporter
from tcsfw.main import DHCP, SSH, UDP, TCP
from tcsfw.verdict import Verdict
from tests.test_model import Setup


class Setup_1(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device().ip("65.21.253.97")
        self.ssh = self.device1 / SSH
        self.ssh.external_activity(ExternalActivity.PASSIVE)


def test_shell_ss_mix():
    su = Setup_1()
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/shell-ss"))
    hs = su.get_hosts()
    # co = su.get_connections()
    assert len(hs) == 6
    h = hs[0]
    assert h.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert h.addresses == {IPAddress.new("169.254.255.255"), IPAddress.new("65.21.253.97"), EntityTag("Device")}
    assert len(h.children) == 6
    s = h.children[0]
    assert s.long_name() == "Device SSH:22"
    assert s.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    s = h.children[1]
    assert s.long_name() == "Device TCP:51337"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[2]
    assert s.long_name() == "Device UDP:68"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[3]
    assert s.long_name() == "Device TCP:41337"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[4]
    assert s.long_name() == "Device UDP:1194"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[5]
    assert s.long_name() == "Device UDP:123"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)


class Setup_2(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        default = self.system.network().mask("0.0.0.0/0")
        vpn = self.system.network("VPN").mask("169.254.0.0/16")
        self.device = self.system.device().in_networks(default, vpn).ip("65.21.253.97").ip("169.254.255.255")
        self.ssh = self.device / SSH
        self.ssh.external_activity(ExternalActivity.OPEN)
        self.dhcp = self.device / DHCP.client().in_network(default)
        # self.dhcp = self.device / UDP(port=68).in_network(default)
        self.udp1 = self.device / UDP(port=123)
        self.udp2 = self.device / UDP(port=1194)
        self.udp3 = self.device / TCP(port=41337)
        self.tcp1 = self.device / TCP(port=51337).in_network(vpn) # .at_address("169.254.255.255")


def test_shell_ss_two_networks():
    su = Setup_2()
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/shell-ss"))
    hs = su.get_hosts()
    co = list(su.get_connections())
    assert len(hs) == 6
    assert len(hs[0].children) == 6
    assert all([h.status_verdict() == (Status.EXPECTED, Verdict.PASS) for h in hs[0].children])

    assert len(co) == 3
    assert co[0].status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert co[1].status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert co[2].status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
