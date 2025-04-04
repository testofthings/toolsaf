import pytest
from unittest.mock import MagicMock
from xml.etree import ElementTree
from io import BytesIO
from datetime import datetime

from toolsaf.adapters.nmap_scan import NMAPScan
from toolsaf.main import ConfigurationException, HTTP
from toolsaf.common.address import Protocol, IPAddress, HWAddress
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.common.traffic import EvidenceSource
from tests.test_model import Setup


@pytest.mark.parametrize(
    "xml_data, names",
    [
        ("<root><runstat></runstat></root>", ["runstat"]),
        ("<root><runstat><finished><test></test></finished></runstat></root>",
         ["runstat", "finished", "test"]
        ),
        ("<root><test><found></found></test></root>", ["test", "not_found"])
    ]
)
def test_get_sub_element(xml_data, names):
    scan = NMAPScan(Setup().get_system())
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    tree = ElementTree.parse(xml_data_bytes)

    if not all([name in xml_data for name in names]):
        with pytest.raises(ConfigurationException):
           scan.get_sub_element(tree, *names)
    else:
        assert scan.get_sub_element(tree, *names).tag == names[-1]


@pytest.mark.parametrize(
    "xml_data, value, exp_result",
    [
        ('<root value="test_value"/>', "value", "test_value"),
        ('<root value="test_value"/>', "not_found", None),
    ]
)
def test_get_from_element(xml_data, value, exp_result):
    scan = NMAPScan(Setup().get_system())
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    element = ElementTree.parse(xml_data_bytes).getroot()

    if exp_result:
        assert scan.get_from_element(element, value) == exp_result
    else:
        with pytest.raises(ConfigurationException):
            scan.get_from_element(element, value)


@pytest.mark.parametrize(
    "xml_data, exp_timestamp",
    [
        (
            '<root><runstats><finished time="1633024800"/></runstats></root>',
            datetime.fromtimestamp(1633024800)
        ),
        (
            '<root><runstats><finished/></runstats></root>',
            None
        ),
        (
            '<root><runstats><finished time="test"/></runstats></root>',
            None
        ),
    ]
)
def test_get_timestamp(xml_data, exp_timestamp):
    scan = NMAPScan(Setup().get_system())
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    root = ElementTree.parse(xml_data_bytes).getroot()

    if exp_timestamp:
        assert scan.get_timestamp(root) == exp_timestamp
    else:
        with pytest.raises(ConfigurationException):
            scan.get_timestamp(root)


@pytest.mark.parametrize(
    "xml_data, exp",
    [
        ('<host><status state="up"/></host>', True),
        ('<host><status state="down"/></host>', False)
    ]
)
def test_host_state_is_up(xml_data, exp):
    scan = NMAPScan(Setup().get_system())
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    element = ElementTree.parse(xml_data_bytes).getroot()

    assert scan.host_state_is_up(element) == exp


@pytest.mark.parametrize(
    "xml_data, exp_ip, exp_hw",
    [
        (
            '<host><address addr="1.2.3.4" addrtype="ipv4"/>' +
            '<address addr="11:11:11:11:11:11" addrtype="mac"/></host>' ,
            IPAddress.new("1.2.3.4"), HWAddress.new("11:11:11:11:11:11")
        ),
        (
            '<host><address addr="1.2.3.4" addrtype="ipv4"/>' +
            '<address addr="" addrtype="unknown"/></host>' ,
            IPAddress.new("1.2.3.4"), None
        ),
        (
            '<host><address addr="" addrtype="unknown"/>' +
            '<address addr="" addrtype="unknown"/></host>' ,
            None, None
        ),
    ]
)
def test_get_address(xml_data, exp_ip, exp_hw):
    scan = NMAPScan(Setup().get_system())
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    host = ElementTree.parse(xml_data_bytes).getroot()

    assert scan.get_addresses(host) == (exp_ip, exp_hw)


@pytest.mark.parametrize(
    "xml_data, exp_protocol, exp_port, exp_service_name",
    [
        ('<port protocol="tcp" portid="80"><service name="http"/></port>', Protocol.TCP, 80, "http"),
        ('<port protocol="udp" portid="53"><service name="ntp"/></port>', Protocol.UDP, 53, "ntp"),
        ('<port protocol="tcp" portid="22"/>', Protocol.TCP, 22, None),
        ('<port protocol="unknown" portid="123"/>', None, 123, None),
    ]
)
def test_get_port_info(xml_data, exp_protocol, exp_port, exp_service_name):
    scan = NMAPScan(Setup().get_system())
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    port_info = ElementTree.parse(xml_data_bytes).getroot()

    if exp_protocol is None:
        with pytest.raises(ConfigurationException):
            scan.get_port_info(port_info)
    else:
        protocol, port, service_name = scan.get_port_info(port_info)
        assert protocol == exp_protocol
        assert port == exp_port
        assert service_name == exp_service_name


def test_add_scans_to_address():
    setup = Setup()
    scan = NMAPScan(setup.get_system())

    xml_data = """
    <host>
        <ports>
            '<port protocol="tcp" portid="80"><service name="http"/></port>'
            '<port protocol="tcp" portid="22"><service name="ssh"/></port>'
        </ports>
    </host>
    """
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    host = ElementTree.parse(xml_data_bytes).getroot()

    ip_addr = IPAddress.new("1.2.3.4")
    device = setup.system.device("Test Device")
    device.new_address_(ip_addr)
    device / HTTP

    scan.add_scans_to_address(ip_addr, host, setup.get_inspector(), MagicMock())
    assert len(device.entity.children) == 2
    http = device.entity.children[0]
    ssh = device.entity.children[1]
    assert http.properties.get(Properties.EXPECTED).verdict == Verdict.PASS
    assert ssh.properties.get(Properties.EXPECTED).verdict == Verdict.FAIL
    assert len(device.entity.properties) == 1
    assert device.entity.properties.get(PropertyKey("nmap")) is None


def test_set_nothing_found():
    setup = Setup()
    scan = NMAPScan(setup.get_system())

    ip_addr = IPAddress.new("1.2.3.4")
    device = setup.system.device("Test Device")
    device.new_address_(ip_addr)

    scan.set_nothing_found(ip_addr, setup.get_inspector(), MagicMock())
    assert len(device.entity.properties) == 2
    assert device.entity.properties.get(PropertyKey("nmap")).verdict == Verdict.PASS


def test_add_scans_to_address_nothing_found():
    setup = Setup()
    scan = NMAPScan(setup.get_system())

    xml_data = """
    <host>
        <ports>
        </ports>
    </host>
    """
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    host = ElementTree.parse(xml_data_bytes).getroot()

    ip_addr = IPAddress.new("1.2.3.4")
    device = setup.system.device("Test Device")
    device.new_address_(ip_addr)

    scan.add_scans_to_address(ip_addr, host, setup.get_inspector(), MagicMock())
    assert len(device.entity.children) == 0
    assert len(device.entity.properties) == 2
    assert device.entity.properties.get(PropertyKey("nmap")).verdict == Verdict.PASS


def test_process_file():
    setup = Setup()
    scan = NMAPScan(setup.get_system())

    xml_data = """
    <nmaprun>
        <runstats>
            <finished time="1633024800"/>
        </runstats>
        <host>
            <status state="up"/>
            <address addr="1.2.3.4" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="80"><service name="http"/></port>
                <port protocol="tcp" portid="22"><service name="ssh"/></port>
            </ports>
        </host>
    </nmaprun>
    """
    xml_data_bytes = BytesIO(xml_data.encode("utf-8"))
    source = EvidenceSource("nmap", "test")

    ip_addr = IPAddress.new("1.2.3.4")
    device = setup.system.device("Test Device")
    device.new_address_(ip_addr)
    device / HTTP

    scan.process_file(xml_data_bytes, "test.xml", setup.get_inspector(), source)

    assert source.timestamp == datetime.fromtimestamp(1633024800)
    assert len(device.entity.children) == 2
    http = device.entity.children[0]
    ssh = device.entity.children[1]
    assert http.properties.get(Properties.EXPECTED).verdict == Verdict.PASS
    assert ssh.properties.get(Properties.EXPECTED).verdict == Verdict.FAIL
