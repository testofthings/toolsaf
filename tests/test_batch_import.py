import pathlib
from tcsfw.address import HWAddress, IPAddress
from tcsfw.batch_import import BatchFileType, BatchImporter, FileMetaInfo
from tcsfw.inspector import Inspector
from tcsfw.matcher import SystemMatcher
from tcsfw.model import IoTSystem
from tests.test_model import simple_setup_1


def test_import_batch_a():
    sb = simple_setup_1()
    im = BatchImporter(Inspector(sb.system))
    im.import_batch(pathlib.Path("tests/samples/batch/batch-a"))
    conn = sb.system.get_connections()
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
    assert result.file_type == BatchFileType.CAPTURE
    assert result.default_include == True
    assert len(result.source.address_map) == 2
    assert result.source.address_map[IPAddress.new("1.2.3.4")] == system.get_entity("Device 1")
    assert result.source.address_map[HWAddress.new("1:2:3:4:5:6")] == system.get_entity("Device 2")
