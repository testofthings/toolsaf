import pytest
import sys
from unittest.mock import MagicMock
from colored import Fore

from tdsaf.common.verdict import Verdict
from tdsaf.core.registry import Registry
from tdsaf.core.result import *
import tdsaf.core.result as res
from tests.test_model import Setup

res.GREEN = Fore.green
res.YELLOW = Fore.rgb(255,220,101)
res.RED = Fore.red

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
    OUTPUT_REDIRECTED = False
    assert r.get_verdict_color(verdict) == exp


@pytest.mark.parametrize(
    "comp, child, exp",
    [
        ([], [], "└──"),
        (["comp1"], [], "│  "),
        ([], ["child1"], "│  "),
        (["comp1"], ["child1"], "│  ")
    ]
)
def test_ge_symbol_for_address(comp, child, exp):
    host = MagicMock()
    host.components = comp
    host.children = child
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
    "idx, comp, child, exp",
    [
        (0, [], [], "├──"),
        (0, ["comp1"], [], "├──"),
        [0, [], ["child1"], "└──"],
        [1, ["comp1", "comp2"], ["child1", "child2"], "├──"]
    ]
)
def test_get_symbol_for_service(idx, comp, child, exp):
    host = MagicMock()
    host.components = comp
    host.children = child
    r = Report(Registry(Setup().get_inspector()))
    assert r.get_symbol_for_service(idx, host) == exp


@pytest.mark.parametrize(
    "idx, comp, exp",
    [
        (0, [], "├──"),
        (0, ["comp1"], "└──"),
        (2, ["comp1"], "└──"),
        (1, ["comp1", "comp2"], "└──")
    ]
)
def test_get_symbol_for_component(idx, comp, exp):
    host = MagicMock()
    host.components = comp
    r = Report(Registry(Setup().get_inspector()))
    assert r.get_symbol_for_component(idx, host) == exp


@pytest.mark.parametrize(
    "verb, show, n_prop, idx, n_comp, exp",
    [
        (True,  [], 1, 0, 0, "├──"),
        (True,  [], 0, 0, 0, "│  "),
        (False, ["properties"], 1, 0, 0, "├──"),
        (False, ["properties"], 0, 0, 2, "│  "),
        (False, [], 0, 1, 3, "│  "),
        (False, [], 0, 1, 2, "└──")
    ]
)
def test_get_symbol_for_info(verb, show, n_prop, idx, n_comp, exp):
    r = Report(Registry(Setup().get_inspector()))
    r.verbose = verb
    r.show = show
    c = MagicMock()
    c.properties = [MagicMock()]*n_prop
    host = MagicMock()
    host.components = [MagicMock()]*n_comp
    assert r.get_symbol_for_info(idx, host, c) == exp
