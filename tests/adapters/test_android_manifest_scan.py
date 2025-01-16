import io
import xml.etree.ElementTree as ET
import pytest

from toolsaf.adapters.android_manifest_scan import AndroidManifestScan
from toolsaf.common.traffic import EvidenceSource
from toolsaf.common.address import EntityTag
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict
from toolsaf.main import ConfigurationException
from toolsaf.common.android import *
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


def do_process(setup: Setup, load_baseline: bool=False):
    scanner = AndroidManifestScan(setup.get_system())
    scanner.load_baseline = load_baseline
    source = EvidenceSource(name="")
    scanner.process_endpoint(EntityTag("Mobile_App"), get_xml_data(), setup.get_inspector(), source)


def test_link_permission_to_category():
    setup = Setup()
    scanner = AndroidManifestScan(setup.get_system())

    assert scanner.link_permission_to_category("CALL_PHONE") == CALLS
    assert scanner.link_permission_to_category("SEND_SMS") == SMS
    assert scanner.link_permission_to_category("READ_CONTACTS") == CONTACTS
    assert scanner.link_permission_to_category("READ_CALENDAR") == CALENDAR
    assert scanner.link_permission_to_category("ACCESS_FINE_LOCATION") == LOCATION
    assert scanner.link_permission_to_category("READ_MEDIA_VIDEO") == STORAGE
    assert scanner.link_permission_to_category("INTERNET") == NETWORK
    assert scanner.link_permission_to_category("TURN_SCREEN_ON") == ADMINISTRATIVE
    assert scanner.link_permission_to_category("BLUETOOTH_CONNECT") == BLUETOOTH
    assert scanner.link_permission_to_category("GET_ACCOUNTS") == ACCOUNT
    assert scanner.link_permission_to_category("BILLING") == BILLING
    assert scanner.link_permission_to_category("CAMERA") == RECORDING
    assert scanner.link_permission_to_category("BODY_SENSORS") == HEALTH
    assert scanner.link_permission_to_category("FAKE_PERMISSION") == UNCATEGORIZED


def test_process_endpoint():
    setup = Setup()
    system = setup.system

    mobile_app = system.mobile("Mobile App")
    mobile_app.software("Mobile App SW")
    mobile_app.set_permissions(RECORDING, STORAGE)

    do_process(setup)

    sw = mobile_app.get_software()
    assert len(sw.properties) == 4 # Three permissions and 1 check
    assert sw.properties[PropertyKey("permission", "Network")].verdict == Verdict.FAIL
    assert sw.properties[PropertyKey("permission", "Recording")].verdict == Verdict.PASS
    assert sw.properties[PropertyKey("permission", "Storage")].verdict == Verdict.FAIL # Not in manifest


def test_process_endpoint_with_load_baseline():
    setup = Setup()
    system = setup.system

    mobile_app = system.mobile("Mobile App")
    mobile_app.software("Mobile App SW")
    mobile_app.set_permissions(RECORDING, STORAGE)

    do_process(setup, load_baseline=True)

    sw = mobile_app.get_software()
    assert sw.properties[PropertyKey("permission", "Network")].verdict == Verdict.PASS
    assert sw.properties[PropertyKey("permission", "Recording")].verdict == Verdict.PASS
    assert sw.properties[PropertyKey("permission", "Storage")].verdict == Verdict.PASS


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
