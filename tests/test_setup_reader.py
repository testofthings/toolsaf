"""Test setup documentation reader"""

import pathlib

from tcsfw.address import DNSName, EntityTag, IPAddress
from tcsfw.batch_import import BatchImporter
from tests.test_model import Setup


class Setup_1(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device()
        self.device2 = self.system.device()


def test_setup_csv():
    su = Setup_1()
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/setup-doc"))
    assert su.device1.entity.addresses == {EntityTag("Device"), DNSName("example.com"), IPAddress.new("192.168.2.5")}
    assert su.device2.entity.addresses == {EntityTag("Device_2")}

