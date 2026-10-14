import json
import pathlib
from unittest.mock import MagicMock

import pytest

from toolsaf.adapters.batch_import import BatchImporter
from toolsaf.adapters.har_scan import HARScan
from toolsaf.adapters.spdx_reader import SPDXReader
from toolsaf.adapters.tools import EntityFileMap
from toolsaf.common.address import EntityTag
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict
from toolsaf.core.components import Software
from toolsaf.core.inspector import Inspector
from toolsaf.main import ConfigurationException
from tests.test_model import Setup


def test_map_by_name_and_tag():
    sw = Software(MagicMock(), "Device 1 SW")
    fm = EntityFileMap[Software](".json")
    fm.add(sw, sw.name, sw.tag)
    assert fm.get_file_names() == {"Device 1 SW.json"}
    assert fm.map_file("Device 1 SW.json") is sw
    assert fm.map_file("Device 1 SW.json") is sw  # same file again is fine
    assert fm.map_file("Other.json") is None
    assert fm.map_file("Device 1 SW.xml") is None
    assert fm.map_file("Device  1 SW.json") is None  # no escaping of file names
    assert fm.map_file(".json") is None
    with pytest.raises(ConfigurationException, match="Data files Device 1 SW.json and Device_1_SW.json"):
        fm.map_file("Device_1_SW.json")  # by tag, but the entity already has a file


def test_map_renamed():
    sw = Software(MagicMock(), "FW")
    sw.name = "Firmware"  # tag remains FW
    for file_name in ["FW.json", "Firmware.json"]:
        fm = EntityFileMap[Software](".json")
        fm.add(sw, sw.name, sw.tag)
        assert fm.map_file(file_name) is sw


def test_map_renamed_original_name_differs_from_tag():
    sw = Software(MagicMock(), "Device 1 SW")
    sw.name = "Firmware"  # tag remains Device_1_SW
    fm = EntityFileMap[Software](".json")
    fm.add(sw, sw.name, sw.tag)
    assert fm.map_file("Device 1 SW.json") is None  # original name, lost by renaming
    assert fm.map_file("Device_1_SW.json") is sw


def test_map_tag_with_underscore_prefix():
    sw = Software(MagicMock(), "1st SW")
    assert sw.tag == EntityTag("_1st_SW")
    fm = EntityFileMap[Software](".json")
    fm.add(sw, sw.name, sw.tag)
    assert fm.map_file("_1st_SW.json") is sw


def test_map_ambiguous_tag():
    sw1 = Software(MagicMock(), "FW")
    sw2 = Software(MagicMock(), "FW")
    sw1.name = "Firmware A"
    sw2.name = "Firmware B"
    assert sw1.tag == sw2.tag == EntityTag("FW")
    fm = EntityFileMap[Software](".json")
    fm.add(sw1, sw1.name, sw1.tag)
    fm.add(sw2, sw2.name, sw2.tag)
    assert fm.map_file("Firmware B.json") is sw2  # name match is fine
    with pytest.raises(ConfigurationException, match="FW.json matches many entities by tag"):
        fm.map_file("FW.json")


def test_har_file_for_renamed_host():
    su = Setup()
    host = su.system.browser("Browser 1")
    host.name("My browser")
    reader = HARScan(su.get_system())
    assert reader.file_name_map.map_file("Browser 1.json") is None  # original name, lost by renaming
    assert reader.file_name_map.map_file("Browser_1.json") is host.entity
    assert reader.get_processed_files() == {"My browser.json"}


def test_batch_spdx_for_renamed_software(tmp_path: pathlib.Path):
    su = Setup()
    sw = su.system.device("Device 1").software("FW")
    sw.sbom(["c1"])
    sw.name("Firmware")

    (tmp_path / "00meta.json").write_text(json.dumps({"file_type": "spdx"}))
    (tmp_path / "FW.json").write_text(json.dumps({"packages": [{"name": "c1"}]}))
    BatchImporter(Inspector(su.get_system())).import_batch(tmp_path)
    assert sw.sw.properties[PropertyKey("component", "c1")].verdict == Verdict.PASS
