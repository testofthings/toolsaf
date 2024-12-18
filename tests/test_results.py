import pytest
from unittest.mock import MagicMock
from typing import List, Tuple
from colored import Fore, Style

from tdsaf.common.verdict import Verdict
from tdsaf.common.property import Properties, PropertyVerdictValue
from tdsaf.core.registry import Registry
from tdsaf.core.model import Connection
from tdsaf.common.basics import ConnectionType
from tdsaf.common.release_info import ReleaseInfo
from tdsaf.core.result import *
from tests.test_model import Setup


def _get_pvv(v: Verdict) -> PropertyVerdictValue:
    return PropertyVerdictValue(v)


@pytest.mark.parametrize(
    "C, is_piped, exp",
    [
        (True, True, True),
        (True, False, True),
        (False, True, True),
        (False, False, False)
    ]
)
def test_use_color(C, is_piped, exp):
    r = Report(Registry(Setup().get_inspector()))
    r.c = C
    sys.stdout.isatty = MagicMock(return_value=is_piped)
    assert r.use_color is exp


@pytest.mark.parametrize(
    "cache, exp",
    [
        ({1: Verdict.PASS, 2: Verdict.INCON, 3: Verdict.IGNORE}, Verdict.PASS),
        ({1: Verdict.PASS, 2: Verdict.INCON, 3: Verdict.FAIL}, Verdict.FAIL),
        ({1: Verdict.INCON, 2: Verdict.IGNORE}, Verdict.INCON),
        ({}, Verdict.INCON)
    ]
)
def test_get_system_verdict(cache: Dict, exp: Verdict):
    r = Report(Registry(Setup().get_inspector()))
    assert r.get_system_verdict(cache) == exp


@pytest.mark.parametrize(
    "verdict, exp",
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
def test_get_verdict_color(verdict, exp):
    r = Report(Registry(Setup().get_inspector()))
    r.c = True
    assert r.get_verdict_color(verdict) == exp


def _get_mock_events(values: List):
    for val in values:
        mock = MagicMock()
        mock.event.evidence.get_reference.return_value = val
        yield mock


@pytest.mark.parametrize(
    "vals, src_cnt, exp",
    [
        ([1,2,3], 3, [1,2,3]),
        ([1,2,3], 2, [1,2]),
        ([2,2,None], 3, [2]),
    ]
)
def test_get_sources(vals: List, src_cnt: int, exp: List):
    r = Report(Registry(Setup().get_inspector()))
    r.source_count = src_cnt
    r.registry = MagicMock()
    r.registry.logging.get_log.return_value = _get_mock_events(vals)
    assert r._get_sources(None) == exp


@pytest.mark.parametrize(
    "p, s, exp",
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
def test_get_properties_to_print(p: Dict, s: List[str], exp: Tuple):
    e = MagicMock()
    e.properties = p
    r = Report(Registry(Setup().get_inspector()))
    r.show = s
    assert r.get_properties_to_print(e) == exp


def test_get_addresses():
    r = Report(Registry(Setup().get_inspector()))
    e = MagicMock()
    e.name = "test"
    e.addresses = ["a", "test", "b"]
    assert r._get_addresses(e) == "a, b"


def test_get_text():
    r = Report(Registry(Setup().get_inspector()))
    k = MagicMock()
    k.get_value_string.return_value = "test:value"
    k.get_explanation.return_value = "comment"
    v = _get_pvv(Verdict.PASS)
    assert r._get_text(k, v) == "test:value # comment"

    k.get_value_string.return_value = "test:value"
    k.get_explanation.return_value = ""
    assert r._get_text(k, _get_pvv(Verdict.PASS)) == "test:value"

    k.get_value_string.return_value = "test:value=verdict.Pass"
    k.get_explanation.return_value = "comment"
    assert r._get_text(k, _get_pvv(Verdict.PASS)) == "test:value # comment"


def test_get_properties():
    r = Report(Registry(Setup().get_inspector()))
    r._get_sources = MagicMock(return_value=["test1", "test2"])
    e = MagicMock()
    e.properties = {Properties.MITM: _get_pvv(Verdict.PASS)}
    r.get_properties_to_print = MagicMock(return_value=[(Properties.MITM, _get_pvv(Verdict.PASS))])
    assert r._get_properties(e) == {"check:mitm": {
        "srcs": ["test1", "test2"],
        "text": "check:mitm",
        "verdict": "Pass"
    }}

    assert r._get_properties(e, parent_srcs=["test1", "test2"]) == {"check:mitm": {
        "srcs": [],
        "text": "check:mitm",
        "verdict": "Pass"
    }}


def test_crop_text():
    r = Report(Registry(Setup().get_inspector()))
    r.width = 10

    assert r._crop_text("0123456789", "", 0)    == "0123456789"
    assert r._crop_text("0123456789123", "", 0) == "0123456..."
    assert r._crop_text("0123456789", "│  ", 0) ==    "0123..."
    assert r._crop_text("0123456789", "", 1)    ==  "012345..."
    assert r._crop_text("0123456789", "│  ", 2) ==      "01..."


def _mock_writer() -> MagicMock:
    w = MagicMock()
    w.output = []
    w.write = lambda txt: w.output.append(txt)
    return w


def test_print_text():
    r = Report(Registry(Setup().get_inspector()))
    writer = _mock_writer()
    r.bold = "B"
    r.reset = "R"
    r.green = "G"
    r._crop_text = MagicMock(return_value="Test")
    r._print_text("Test", "Pass", "│  ", writer, use_bold=True)
    assert writer.output[0] == \
        "G[Pass]           R│  GBTestR\n"

    r._print_text("Test", "Pass", "│  ", writer)
    assert writer.output[1] == \
        "G[Pass]           R│  GTestR\n"

    r._print_text("Test", None, "│  ", writer)
    assert writer.output[2] == \
        "                 │  Test\n"


def test_get_sub_structure():
    r = Report(Registry(Setup().get_inspector()))
    r._get_sources = MagicMock(return_value=[1, 2])
    r._get_addresses = MagicMock(return_value=".fi, .com")
    r._get_properties = MagicMock(return_value = {"test1": {"a": 1}, "test2": {"b": 2}})
    e = MagicMock(spec=Host)
    e.status_string.return_value = "Expected/Pass"
    assert r._get_sub_structure(e) == {
        "srcs": [1, 2],
        "verdict": "Expected/Pass",
        "address": ".fi, .com",
        "test1": {"a": 1},
        "test2": {"b": 2}
    }

    e = MagicMock()
    e.status_string.return_value = "Expected/Pass"
    assert r._get_sub_structure(e) == {
        "srcs": [1, 2],
        "verdict": "Expected/Pass",
        "address": None,
        "test1": {"a": 1},
        "test2": {"b": 2}
    }



@pytest.mark.parametrize(
    "c_type, c_status, verdict, exp",
    [
        (ConnectionType.LOGICAL, "", Verdict.PASS, "Logical"),
        (ConnectionType.LOGICAL, "", Verdict.FAIL, "Logical"),
        (ConnectionType.ENCRYPTED, "Ext", Verdict.INCON, "Ext"),
        (ConnectionType.ENCRYPTED, "Exp", Verdict.PASS, "Exp/Pass"),
        (ConnectionType.ENCRYPTED, "Exp", Verdict.FAIL, "Exp/Fail"),
    ]
)
def test_get_connection_status(c_type: ConnectionType, c_status: str, verdict: Verdict, exp: str):
    r = Report(Registry(Setup().get_inspector()))
    connection = MagicMock()
    connection.con_type = c_type
    connection.status.value = c_status
    connection.get_verdict = MagicMock(return_value=verdict)
    assert r.get_connection_status(connection, {}) == exp

