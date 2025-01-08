import pytest
from xml.etree import ElementTree
from io import BytesIO
from datetime import datetime

from tdsaf.adapters.nmap_scan import NMAPScan
from tdsaf.main import ConfigurationException
from tdsaf.common.address import Protocol
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
