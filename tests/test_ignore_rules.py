from unittest.mock import MagicMock

from toolsaf.core.ignore_rules import IgnoreRules
from toolsaf.builder_backend import IgnoreRulesBackend
from toolsaf.common.property import PropertyKey, PropertyVerdictValue
from toolsaf.common.verdict import Verdict
from toolsaf.main import TCP, SSH
from test_model import Setup


def test_ignore():
    system = Setup().system
    system.ignore_backend.ignore_rules.new_rule = MagicMock()

    result = system.ignore(file_type="test-type")
    assert isinstance(result, IgnoreRulesBackend)
    system.ignore_backend.ignore_rules.new_rule.assert_called_once_with("test-type")


def test_get_rules():
    system = Setup().system
    assert isinstance(system.ignore_backend.get_rules(), IgnoreRules)


def test_new_rule():
    ir = IgnoreRules()
    assert ir._current_rule is None

    ir.new_rule(file_type="test-type1")
    assert ir._current_rule
    assert ir._current_rule.file_type == "test-type1"

    ir.new_rule(file_type="test-type2")
    assert ir._current_rule.file_type == "test-type2"


def test_properties():
    system = Setup().system
    system.ignore("test-type").properties("abc:efg", "123:456")
    rules = system.ignore_backend.get_rules()
    assert rules._current_rule.properties == [
        PropertyKey("abc", "efg"), PropertyKey("123", "456")
    ]


def test_at():
    system = Setup().system
    device = system.device("Test Device")
    system.ignore("test-type").at(device / SSH, device / TCP(1))
    rules = system.ignore_backend.get_rules()
    assert rules._current_rule.at == [
        (device / SSH).entity, (device / TCP(1)).entity
    ]

    software = device.software("Test SW").sw
    system.ignore("test-type").at(device.software("Test SW"))
    rules = system.ignore_backend.get_rules()
    assert rules._current_rule.at == [
        software
    ]


def test_because():
    system = Setup().system
    system.ignore("test-type").because("test reason")
    rules = system.ignore_backend.get_rules()
    assert rules._current_rule.explanation == "test reason"


def test_update_based_on_rules():
    system = Setup().system
    device = system.device()
    entity = (device / SSH).entity

    # Ignore everything
    system.ignore("test-type")
    key = PropertyKey("abc", "efg")
    pvv = PropertyVerdictValue(Verdict.FAIL, "Failed")
    system.ignore_backend.get_rules().update_based_on_rules("test-type", key, pvv, entity)
    assert pvv.verdict == Verdict.IGNORE
    assert pvv.explanation == "Failed"

    # Ignore key "abc" only
    system.ignore("test-type2").properties("abc").because("test")
    pvv = PropertyVerdictValue(Verdict.FAIL, "Failed")
    system.ignore_backend.get_rules().update_based_on_rules("test-type2", key, pvv, entity)
    assert pvv.verdict == Verdict.FAIL
    assert pvv.explanation == "Failed"

    # Reason added
    system.ignore("test-type2").properties("abc:efg").because("test")
    system.ignore_backend.get_rules().update_based_on_rules("test-type2", key, pvv, entity)
    assert pvv.verdict == Verdict.IGNORE
    assert pvv.explanation == "test"

    # With different at
    system.ignore("test-type3").properties("abc:efg").at(device / TCP(1))
    pvv = PropertyVerdictValue(Verdict.FAIL, "Failed")
    system.ignore_backend.get_rules().update_based_on_rules("test-type3", key, pvv, entity)
    assert pvv.verdict == Verdict.FAIL
    assert pvv.explanation == "Failed"

    # With same at
    system.ignore("test-type3").properties("abc:efg").at(device / SSH)
    pvv = PropertyVerdictValue(Verdict.FAIL, "Failed")
    system.ignore_backend.get_rules().update_based_on_rules("test-type3", key, pvv, entity)
    assert pvv.verdict == Verdict.IGNORE
    assert pvv.explanation == "Failed"
