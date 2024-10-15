"""Test shell command output parsing"""

import pathlib

from tcsfw.batch_import import BatchImporter
from tcsfw.components import OperatingSystem
from tcsfw.property import PropertyKey
from tcsfw.verdict import Verdict
from tests.test_model import Setup


class Setup_1(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device().hw("1:0:0:0:0:1")
        self.device2 = self.system.device().ip("192.168.0.2")


def test_shell_ps_baseline():
    su = Setup_1()
    BatchImporter(su.get_inspector(), load_baseline=True).import_batch(pathlib.Path("tests/samples/shell-ps"))
    os = OperatingSystem.get_os(su.device1.entity, add=False)
    assert os.process_map == {
        '100070': ['^postgres:'],
        'root': ['^/opt/venv.d/production/bin/python', '^highball'],
        'john': ['^acommand']
    }


def test_shell_ps_pass():
    su = Setup_1()
    su.device1.os().processes({
        'root': ['^highball', '^.*/bin/python'],
    })
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/shell-ps"))
    os = OperatingSystem.get_os(su.device1.entity, add=False)
    assert PropertyKey("process", "root").get_verdict(os.properties) == Verdict.PASS


def test_shell_ps_fail():
    su = Setup_1()
    su.device1.os().processes({
        'root': ['highball'],
    })
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/shell-ps"))
    os = OperatingSystem.get_os(su.device1.entity, add=False)
    assert PropertyKey("process", "root").get_verdict(os.properties) == Verdict.FAIL
