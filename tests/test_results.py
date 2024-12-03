import pytest
from unittest.mock import MagicMock
from colored import Fore, Style

from tdsaf.common.verdict import Verdict
from tdsaf.common.property import PropertyVerdictValue
from tdsaf.core.registry import Registry
from tdsaf.common.basics import ConnectionType
from tdsaf.core.result import *
from tests.test_model import Setup


def _get_pvv(v: Verdict) -> PropertyVerdictValue:
    return PropertyVerdictValue(v)


def _mock_array(n: int) -> list[MagicMock]:
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
def test_get_system_verdict(cache: dict, exp: Verdict):
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
    "text, exp",
    [
        ("test", "test"),
        (f"test{Style.reset}\n", f"test{Style.reset}\n"),
        (f"{'t'*10}{Style.reset}\n", f"ttttttt...{Style.reset}\n")
    ]
)
def test_crop_text(text, exp):
    r = Report(Registry(Setup().get_inspector()))
    r.width = 10
    r.c = True
    assert r.crop_text(text) == exp


@pytest.mark.parametrize(
    "p, s, exp",
    [
        (
            {Properties.EXPECTED: Verdict.PASS}, ["all"], ([], 0)
        ),
        (
            {Properties.EXPECTED: Verdict.PASS, Properties.MITM: Verdict.IGNORE},
            ["all"], ([(Properties.MITM, Verdict.IGNORE)], 1)
        ),
        (
            {Properties.MITM: Verdict.PASS}, [], ([], 0),
        ),
        (
            {Properties.MITM: _get_pvv(Verdict.FAIL), Properties.FUZZ: _get_pvv(Verdict.IGNORE)},
            ["ignored"],
            ([(Properties.MITM, _get_pvv(Verdict.FAIL)), (Properties.FUZZ, _get_pvv(Verdict.IGNORE))], 2)
        ),
        (
            {Properties.MITM: _get_pvv(Verdict.PASS), Properties.FUZZ: _get_pvv(Verdict.IGNORE)},
            ["properties"], ([(Properties.MITM, _get_pvv(Verdict.PASS))], 1)
        ),
        (
            {Properties.MITM: _get_pvv(Verdict.PASS), Properties.FUZZ: _get_pvv(Verdict.IGNORE)},
            ["properties", "ignored"],
            ([(Properties.MITM, _get_pvv(Verdict.PASS)), (Properties.FUZZ, _get_pvv(Verdict.IGNORE))], 2)
        )
    ]
)
def test_get_properties_to_print(p: dict, s: list[str], exp: tuple):
    e = MagicMock()
    e.properties = p
    r = Report(Registry(Setup().get_inspector()))
    r.show = s
    assert r.get_properties_to_print(e) == exp


@pytest.mark.parametrize(
    "n_comp, n_child, exp",
    [
        (0, 0, "└──"),
        (1, 0, "│  "),
        (0, 1, "│  "),
        (1, 1, "│  ")
    ]
)
def test_ge_symbol_for_address(n_comp, n_child, exp):
    host = _get_mock_host(n_comp, n_child)
    r = Report(Registry(Setup().get_inspector()))
    assert r.get_symbol_for_addresses(host) == exp


@pytest.mark.parametrize(
    "idx, total, exp",
    [
        (0, 2, "├──"),
        (1, 2, "└──")
    ]
)
def test_get_symbol_for_property(idx, total, exp):
    r = Report(Registry(Setup().get_inspector()))
    assert r.get_symbol_for_property(idx, total) == exp


@pytest.mark.parametrize(
    "idx, n_comp, n_child, exp",
    [
        (0, 0, 0, "├──"),
        (0, 1, 0, "├──"),
        [0, 0, 1, "└──"],
        [1, 2, 2, "├──"]
    ]
)
def test_get_symbol_for_service(idx, n_comp, n_child, exp):
    host = _get_mock_host(n_comp, n_child)
    r = Report(Registry(Setup().get_inspector()))
    assert r.get_symbol_for_service(idx, host) == exp


@pytest.mark.parametrize(
    "idx, n_comp, exp",
    [
        (0, 0, "├──"),
        (0, 1, "└──"),
        (2, 1, "└──"),
        (1, 2, "└──")
    ]
)
def test_get_symbol_for_component(idx, n_comp, exp):
    host = _get_mock_host(n_comp)
    r = Report(Registry(Setup().get_inspector()))
    assert r.get_symbol_for_component(idx, host) == exp


@pytest.mark.parametrize(
    "show, n_prop, idx, n_comp, exp",
    [
        (["all"], 1, 0, 0, "├──"),
        (["all"], 0, 0, 0, "│  "),
        (["properties"], 1, 0, 0, "├──"),
        (["properties"], 0, 0, 2, "│  "),
        ([], 0, 1, 3, "│  "),
        ([], 0, 1, 2, "└──")
    ]
)
def test_get_symbol_for_info(show, n_prop, idx, n_comp, exp):
    r = Report(Registry(Setup().get_inspector()))
    r.show = show
    c = MagicMock()
    c.properties = [MagicMock()]*n_prop
    host = _get_mock_host(n_comp)
    assert r.get_symbol_for_info(idx, host, c) == exp


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
