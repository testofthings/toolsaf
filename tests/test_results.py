import pytest
from unittest.mock import MagicMock
from typing import List, Tuple, Dict
from colored import Fore

from tdsaf.common.verdict import Verdict
from tdsaf.common.property import Properties, PropertyVerdictValue
from tdsaf.main import HTTP, TLS
from tdsaf.core.registry import Registry
from tdsaf.common.basics import ConnectionType
from tdsaf.core.result import *
from tests.test_model import Setup


def _get_pvv(verdict: Verdict) -> PropertyVerdictValue:
    return PropertyVerdictValue(verdict)


@pytest.mark.parametrize(
    "use_color_flag, is_piped, expected",
    [
        (True, True, True),
        (True, False, True),
        (False, True, True),
        (False, False, False)
    ]
)
def test_use_color(use_color_flag, is_piped, expected):
    report = Report(Registry(Setup().get_inspector()))
    report.use_color_flag = use_color_flag
    sys.stdout.isatty = MagicMock(return_value=is_piped)
    assert report.use_color is expected


@pytest.mark.parametrize(
    "cache, expected",
    [
        ({1: Verdict.PASS, 2: Verdict.INCON, 3: Verdict.IGNORE}, Verdict.PASS),
        ({1: Verdict.PASS, 2: Verdict.INCON, 3: Verdict.FAIL}, Verdict.FAIL),
        ({1: Verdict.INCON, 2: Verdict.IGNORE}, Verdict.INCON),
        ({}, Verdict.INCON)
    ]
)
def test_get_system_verdict(cache: Dict, expected: Verdict):
    report = Report(Registry(Setup().get_inspector()))
    assert report.get_system_verdict(cache) == expected


@pytest.mark.parametrize(
    "verdict, expected",
    [
        (Verdict.INCON, ""),
        (Verdict.FAIL, Fore.red),
        (Verdict.PASS, Fore.green),
        (Verdict.IGNORE, Fore.rgb(255,220,101)),
        ("a/fail", Fore.red),
        ("a/pass", Fore.green),
        ("a/incon", ""),
        ("fail", Fore.red),
        ("pass", Fore.green),
        ("ignore", Fore.rgb(255,220,101)),
        ("incon", "")
    ]
)
def test_get_verdict_color(verdict, expected):
    report = Report(Registry(Setup().get_inspector()))
    report.use_color_flag = True
    assert report.get_verdict_color(verdict) == expected


def _get_mock_events(values: List):
    for value in values:
        mock = MagicMock()
        mock.event.evidence.get_reference.return_value = value
        yield mock


@pytest.mark.parametrize(
    "values, source_count, expected",
    [
        ([1,2,3], 3, [1,2,3]),
        ([1,2,3], 2, [1,2]),
        ([2,2,None], 3, [2]),
    ]
)
def test_get_sources(values: List, source_count: int, expected: List):
    report = Report(Registry(Setup().get_inspector()))
    report.source_count = source_count
    report.registry = MagicMock()
    report.registry.logging.get_log.return_value = _get_mock_events(values)
    assert report._get_sources(None) == expected


@pytest.mark.parametrize(
    "properties, show, expected",
    [
        (
            {Properties.EXPECTED: Verdict.PASS}, ["all"], []
        ),
        (
            {Properties.EXPECTED: Verdict.PASS, Properties.MITM: Verdict.IGNORE},
            ["all"], [(Properties.MITM, Verdict.IGNORE)]
        ),
        (
            {Properties.MITM: Verdict.PASS}, [], [],
        ),
        (
            {Properties.MITM: _get_pvv(Verdict.FAIL), Properties.FUZZ: _get_pvv(Verdict.IGNORE)},
            ["ignored"],
            [(Properties.MITM, _get_pvv(Verdict.FAIL)), (Properties.FUZZ, _get_pvv(Verdict.IGNORE))]
        ),
        (
            {Properties.MITM: _get_pvv(Verdict.PASS), Properties.FUZZ: _get_pvv(Verdict.IGNORE)},
            ["properties"], [(Properties.MITM, _get_pvv(Verdict.PASS))]
        ),
        (
            {Properties.MITM: _get_pvv(Verdict.PASS), Properties.FUZZ: _get_pvv(Verdict.IGNORE)},
            ["properties", "ignored"],
            [(Properties.MITM, _get_pvv(Verdict.PASS)), (Properties.FUZZ, _get_pvv(Verdict.IGNORE))]
        )
    ]
)
def test_get_properties_to_print(properties: Dict, show: List[str], expected: Tuple):
    entity = MagicMock()
    entity.properties = properties
    report = Report(Registry(Setup().get_inspector()))
    report.show = show
    assert report.get_properties_to_print(entity) == expected


def test_get_addresses():
    report = Report(Registry(Setup().get_inspector()))
    entity = MagicMock()
    entity.name = "test"
    entity.addresses = ["a", "test", "b"]
    assert report._get_addresses(entity) == "a, b"


def test_get_text():
    report = Report(Registry(Setup().get_inspector()))
    key = MagicMock()
    key.get_value_string.return_value = "test:value"
    key.get_explanation.return_value = "comment"
    value = _get_pvv(Verdict.PASS)
    assert report._get_text(key, value) == "test:value # comment"

    key.get_value_string.return_value = "test:value"
    key.get_explanation.return_value = ""
    assert report._get_text(key, _get_pvv(Verdict.PASS)) == "test:value"

    key.get_value_string.return_value = "test:value=verdict.Pass"
    key.get_explanation.return_value = "comment"
    assert report._get_text(key, _get_pvv(Verdict.PASS)) == "test:value # comment"


def test_get_properties():
    report = Report(Registry(Setup().get_inspector()))
    report._get_sources = MagicMock(return_value=["test1", "test2"])
    entity = MagicMock()
    entity.properties = {Properties.MITM: _get_pvv(Verdict.PASS)}
    report.get_properties_to_print = MagicMock(return_value=[(Properties.MITM, _get_pvv(Verdict.PASS))])
    assert report._get_properties(entity) == {"check:mitm": {
        "srcs": ["test1", "test2"],
        "text": "check:mitm",
        "verdict": "Pass"
    }}

    assert report._get_properties(entity) == {"check:mitm": {
        "srcs": ["test1", "test2"],
        "text": "check:mitm",
        "verdict": "Pass"
    }}


def test_crop_text():
    report = Report(Registry(Setup().get_inspector()))
    report.width = 10

    assert report._crop_text("0123456789", "", 0)    == "0123456789"
    assert report._crop_text("0123456789123", "", 0) == "0123456..."
    assert report._crop_text("0123456789", "│  ", 0) ==    "0123..."
    assert report._crop_text("0123456789", "", 1)    ==  "012345..."
    assert report._crop_text("0123456789", "│  ", 2) ==      "01..."


def _mock_writer() -> MagicMock:
    writer = MagicMock()
    writer.output = []
    writer.write = lambda text: writer.output.append(text)
    return writer


def test_print_text():
    report = Report(Registry(Setup().get_inspector()))
    writer = _mock_writer()
    report.bold = "B"
    report.reset = "R"
    report.green = "G"
    report._crop_text = MagicMock(return_value="Test")
    report._print_text("Test", "Pass", "│  ", writer, use_bold=True)
    assert writer.output[0] == \
        "G[Pass]           R│  GBTestR\n"

    report._print_text("Test", "Pass", "│  ", writer)
    assert writer.output[1] == \
        "G[Pass]           R│  GTestR\n"

    report._print_text("Test", None, "│  ", writer)
    assert writer.output[2] == \
        "                 │  Test\n"


def test_get_sub_structure():
    report = Report(Registry(Setup().get_inspector()))
    report._get_sources = MagicMock(return_value=[1, 2])
    report._get_addresses = MagicMock(return_value=".fi, .com")
    report._get_properties = MagicMock(return_value = {"test1": {"a": 1}, "test2": {"b": 2}})
    entity = MagicMock(spec=Host)
    entity.status_string.return_value = "Expected/Pass"
    assert report._get_sub_structure(entity) == {
        "srcs": [1, 2],
        "verdict": "Expected/Pass",
        "address": ".fi, .com",
        "test1": {"a": 1},
        "test2": {"b": 2}
    }

    entity = MagicMock()
    entity.status_string.return_value = "Expected/Pass"
    assert report._get_sub_structure(entity) == {
        "srcs": [1, 2],
        "verdict": "Expected/Pass",
        "address": "",
        "test1": {"a": 1},
        "test2": {"b": 2}
    }


def test_build_host_structure():
    setup = Setup()
    report = Report(Registry(setup.get_inspector()))
    report.show = "properties"
    report._get_sources = MagicMock(return_value=["@1", "@2"])

    mobile = setup.system.mobile("Mobile App")
    device = setup.system.device("Device")
    mobile.software("Test")
    mobile.entity.components[0].properties = {
        Properties.FUZZ: _get_pvv(Verdict.FAIL)
    }
    mobile >> device / HTTP
    mobile.entity.status_string = MagicMock(return_value="Expected/Pass")
    mobile.entity.properties = {
        Properties.MITM: _get_pvv(Verdict.PASS)
    }

    assert report.build_host_structure(setup.system.system.get_hosts()) == {
        "Mobile App": {
            "srcs": ["@1", "@2"], "address": "Mobile_App", "verdict": "Expected/Pass",
            "check:mitm": {"srcs": ["@1", "@2"], "verdict": "Pass", "text": "check:mitm"},
            "Test [Component]": {
                "srcs": ["@1", "@2"], "address": "", "verdict": "Expected",
                "check:fuzz": {"srcs": ["@1", "@2"], "verdict": "Fail", "text": "check:fuzz"},
            },
        },
        "Device": {
            "srcs": ["@1", "@2"], "address": "", "verdict": "Expected",
            "HTTP:80": {"srcs": ["@1", "@2"], "address": "", "verdict": "Expected"},
        }
    }


def test_print_host_structure():
    report = Report(Registry(Setup().get_inspector()))
    structure = {
        "Mobile App": {
            "srcs": [], "address": "Mobile_App", "verdict": "Expected/Pass",
            "check:mitm": {"srcs": [], "verdict": "Pass", "text": "check:mitm"},
            "Test [Component]": {
                "srcs": ["1", "2"], "address": "", "verdict": "Expected",
                "check:fuzz": {"srcs": [], "verdict": "Fail", "text": "check:fuzz"},
            },
        },
        "Device": {
            "srcs": ["1", "2"], "address": "Device", "verdict": "Expected",
            "HTTP:80": {"srcs": ["1", "2"], "address": "", "verdict": "Expected"},
            "TLS:443": {"srcs": [], "address": "", "verdict": ""},
        }
    }

    writer = _mock_writer()
    report._print_host_structure(0, structure, writer, "│  ", False)

    assert ''.join(writer.output) == \
        "[Expected/Pass]  ├──Mobile App\n"                + \
        "                 │  │  Addresses: Mobile_App\n"  + \
        "[Pass]           │  ├──check:mitm\n"             + \
        "[Expected]       │  └──Test [Component]\n"       + \
        "                 │     │  @1\n"                  + \
        "                 │     │  @2\n"                  + \
        "[Fail]           │     └──check:fuzz\n"          + \
        "[Expected]       └──Device\n"                    + \
        "                    │  @1\n"                     + \
        "                    │  @2\n"                     + \
        "                    │  Addresses: Device\n"      + \
        "[Expected]          ├──HTTP:80\n"                + \
        "                    │     @1\n"                  + \
        "                    │     @2\n"                  + \
        "                    └──TLS:443\n"


@pytest.mark.parametrize(
    "connection_type, connection_status, verdict, expected",
    [
        (ConnectionType.LOGICAL, "", Verdict.PASS, "Logical"),
        (ConnectionType.LOGICAL, "", Verdict.FAIL, "Logical"),
        (ConnectionType.ENCRYPTED, "Ext", Verdict.INCON, "Ext"),
        (ConnectionType.ENCRYPTED, "Exp", Verdict.PASS, "Exp/Pass"),
        (ConnectionType.ENCRYPTED, "Exp", Verdict.FAIL, "Exp/Fail"),
    ]
)
def test_get_connection_status(connection_type: ConnectionType, connection_status: str, verdict: Verdict, expected: str):
    report = Report(Registry(Setup().get_inspector()))
    connection = MagicMock()
    connection.con_type = connection_type
    connection.status.value = connection_status
    connection.get_verdict = MagicMock(return_value=verdict)
    assert report.get_connection_status(connection, {}) == expected


def test_build_connection_structure():
    setup = Setup()
    report = Report(Registry(setup.get_inspector()))
    report.show = "properties"
    report.get_connection_status = MagicMock(return_value="Expected/Pass")


    mobile = setup.system.mobile("Mobile App")
    device = setup.system.device("Device")

    mobile >> device / HTTP / TLS

    for connection in setup.get_system().get_connections():
        connection.properties = {Properties.MITM: _get_pvv(Verdict.PASS)}

    assert report.build_connection_structure(setup.get_system().get_connections(), {}) == {
        "connections": [
            {
                "verdict": "Expected/Pass",
                "source": "Mobile App",
                "target": "Device HTTP:80",
                "srcs": [],
                "check:mitm": {"srcs": [], "verdict": "Pass", "text": "check:mitm"}
            },
            {
                "verdict": "Expected/Pass",
                "source": "Mobile App",
                "target": "Device TLS:443",
                "srcs": [],
                "check:mitm": {"srcs": [], "verdict": "Pass", "text": "check:mitm"}
            }
        ]
    }


def test_print_connection_structure():
    report = Report(Registry(Setup().get_inspector()))
    structure = {
        "connections": [
            {
                "verdict": "Expected/Pass",
                "source": "Mobile App",
                "target": "Device HTTP:80",
                "srcs": ["1"],
                "check:mitm": {"srcs": [], "verdict": "Pass", "text": "check:mitm"}
            },
            {
                "verdict": "Expected/Pass",
                "source": "Mobile App",
                "target": "Device TLS:443",
                "srcs": [],
                "check:mitm": {"srcs": ["1", "2"], "verdict": "Pass", "text": "check:mitm"}
            }
        ]
    }

    writer = _mock_writer()
    for connection in structure["connections"]:
        report._print_connection_structure(connection, writer)

    assert ''.join(writer.output) == \
        "[Expected/Pass]  Mobile App                       Device HTTP:80\n" + \
        "                 │  @1\n"                                           + \
        "[Pass]           └──check:mitm\n"                                   + \
        "[Expected/Pass]  Mobile App                       Device TLS:443\n" + \
        "[Pass]           └──check:mitm\n"                                   + \
        "                       @1\n"                                        + \
        "                       @2\n"
