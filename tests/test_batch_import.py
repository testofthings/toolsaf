import pathlib
from tcsfw.address import HWAddress, IPAddress
from tcsfw.batch_import import BatchImporter, FileMetaInfo, LabelFilter
from tcsfw.inspector import Inspector
from tests.test_model import Setup, simple_setup_1

class Setup_1(Setup):
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device().hw("1:0:0:0:0:1")


def test_import_batch_a():
    su = Setup_1()
    BatchImporter(Inspector(su.get_system())).import_batch(pathlib.Path("tests/samples/batch/batch-a"))
    conn = su.get_system().get_connections()
    assert len(conn) == 2


def test_import_batch_a_not():
    su = Setup_1()
    bi = BatchImporter(Inspector(su.get_system()))
    bi.label_filter = LabelFilter("X")
    bi.import_batch(pathlib.Path("tests/samples/batch/batch-a"))
    conn = su.get_system().get_connections()
    assert len(conn) == 0


def test_import_batch_a_yes():
    su = Setup_1()
    bi = BatchImporter(Inspector(su.get_system()))
    bi.label_filter = LabelFilter("X,batch-a")
    bi.import_batch(pathlib.Path("tests/samples/batch/batch-a"))
    conn = su.get_system().get_connections()
    assert len(conn) == 2


def test_parse_from_json():
    json_data = {
        "file_type": "capture",
        "include": True,
        "addresses": {
            "1.2.3.4": "Device 1",
            "1:2:3:4:5:6|hw": "Device 2"
        }
    }
    sb = simple_setup_1()
    system = sb.system
    result = FileMetaInfo.parse_from_json(json_data, "pcap-x", system)

    assert result.label == "pcap-x"
    assert result.file_type == "capture"
    assert result.default_include is True
    assert len(result.source.address_map) == 2
    assert result.source.address_map[IPAddress.new("1.2.3.4")] == system.get_entity("Device 1")
    assert result.source.address_map[HWAddress.new("1:2:3:4:5:6")] == system.get_entity("Device 2")
