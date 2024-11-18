import io
import xml.etree.ElementTree as ET
import pytest

from tdsaf.adapters.android_manifest_scan import AndroidManifestScan
from tdsaf.common.traffic import EvidenceSource
from tdsaf.common.address import EntityTag
from tdsaf.common.property import PropertyKey
from tdsaf.common.verdict import Verdict
from tdsaf.main import ConfigurationException
from tests.test_model import Setup


def get_xml_data():
    manifest = ET.Element("manifest")
    manifest.set("xmlns:android", "http://schemas.android.com/apk/res/android")
    ET.SubElement(manifest, "uses-permission").set(
        "android:name", "android.permission.INTERNET")
    ET.SubElement(manifest, "uses-permission").set(
        "android:name", "android.permission.CAMERA"
    )
    tree = ET.ElementTree(manifest)
    xml_data = io.BytesIO()
    tree.write(xml_data, xml_declaration=True)
    xml_data.seek(0)
    return io.BufferedReader(xml_data)


def do_process(setup: Setup):
    scanner = AndroidManifestScan(setup.get_system())
    source = EvidenceSource(name="")
    scanner.process_endpoint(EntityTag("Mobile_App"), get_xml_data(), setup.get_inspector(), source)


def test_process_endpoint():
    setup = Setup()
    system = setup.system

    mobile_app = system.mobile("Mobile App")
    mobile_app.software("Mobile App SW")

    do_process(setup)

    sw = mobile_app.get_software()
    assert len(sw.properties) == 3 # Two permissions and 1 check
    assert sw.properties[PropertyKey("permission", "INTERNET")].verdict == Verdict.FAIL
    assert sw.properties[PropertyKey("permission", "CAMERA")].verdict == Verdict.FAIL


def test_process_endpoint_fails_when_not_mobile_app():
    setup = Setup()
    system = setup.system

    mobile_app = system.device("Device")
    mobile_app.software("DeviceSW")

    with pytest.raises(ConfigurationException):
        do_process(setup)


def test_process_endpoint_fails_when_2_sw():
    setup = Setup()
    system = setup.system

    mobile_app = system.mobile("Mobile App")
    mobile_app.software("Mobile App SW")
    mobile_app.software("Mobile App SW 2")

    with pytest.raises(ConfigurationException):
        do_process(setup)
