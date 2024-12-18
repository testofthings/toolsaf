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


def _mock_array(n: int) -> List[MagicMock]:
    return [MagicMock()] * n


def _get_mock_host(n_components: int=0, n_children: int=0):
    host = MagicMock()
    if n_components:
        host.components = _mock_array(n_components)
    if n_children:
        host.children = _mock_array(n_children)
    return host

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


def _mock_writer() -> MagicMock:
    w = MagicMock()
    w.output = []
    w.write = lambda txt: w.output.append(txt)
    return w


def _get_properties(keys: List[str], verdicts: List[Verdict]) -> Dict:
    return {
        Properties.FUZZ.append_key(k): _get_pvv(v)
            for k, v in zip(keys, verdicts)
    }
