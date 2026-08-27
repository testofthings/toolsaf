from unittest.mock import MagicMock

from toolsaf.core.ignore_rules import IgnoreRules
from toolsaf.core.inspector import Inspector
from toolsaf.core.event_interface import PropertyAddressEvent, PropertyEvent
from toolsaf.builder_backend import IgnoreRulesBackend
from toolsaf.common.address import IPAddress
from toolsaf.common.property import PropertyKey, PropertyVerdictValue
from toolsaf.common.traffic import Evidence, EvidenceSource
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
    assert rules._current_rule.properties == {
        PropertyKey("abc", "efg"), PropertyKey("123", "456")
    }


def test_at():
    system = Setup().system
    device = system.device("Test Device")
    system.ignore("test-type").at(device / SSH, device / TCP(1))
    rules = system.ignore_backend.get_rules()
    assert rules._current_rule.at == {
        (device / SSH).entity.get_system_address().get_parseable_value(),
        (device / TCP(1)).entity.get_system_address().get_parseable_value()
    }

    software = device.software("Test SW").sw
    system.ignore("test-type").at(device.software("Test SW"))
    rules = system.ignore_backend.get_rules()
    assert rules._current_rule.at == {
        software.get_system_address().get_parseable_value()
    }


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
    new_pvv = system.ignore_backend.get_rules().update_based_on_rules("test-type", key, pvv, entity)
    assert new_pvv.verdict == Verdict.IGNORE
    assert new_pvv.explanation == "Failed"

    # Ignore key "abc" only
    system.ignore("test-type2").properties("abc").because("test")
    pvv = PropertyVerdictValue(Verdict.FAIL, "Failed")
    new_pvv = system.ignore_backend.get_rules().update_based_on_rules("test-type2", key, pvv, entity)
    assert new_pvv.verdict == Verdict.FAIL
    assert new_pvv.explanation == "Failed"

    # Reason added
    system.ignore("test-type2").properties("abc:efg").because("test")
    new_pvv = system.ignore_backend.get_rules().update_based_on_rules("test-type2", key, pvv, entity)
    assert new_pvv.verdict == Verdict.IGNORE
    assert new_pvv.explanation == "test"

    # With different at
    system.ignore("test-type3").properties("abc:efg").at(device / TCP(1))
    pvv = PropertyVerdictValue(Verdict.FAIL, "Failed")
    new_pvv = system.ignore_backend.get_rules().update_based_on_rules("test-type3", key, pvv, entity)
    assert new_pvv.verdict == Verdict.FAIL
    assert new_pvv.explanation == "Failed"

    # With same at
    system.ignore("test-type3").properties("abc:efg").at(device / SSH)
    pvv = PropertyVerdictValue(Verdict.FAIL, "Failed")
    new_pvv = system.ignore_backend.get_rules().update_based_on_rules("test-type3", key, pvv, entity)
    assert new_pvv.verdict == Verdict.IGNORE
    assert new_pvv.explanation == "Failed"


def test_rules_applied_to_events():
    system = Setup().system
    device = system.device().ip("1.2.3.4")
    system.ignore("test-type").properties("abc:efg").at(device).because("test reason")
    inspector = Inspector(system.system, system.ignore_backend.get_rules())
    key = PropertyKey("abc", "efg")
    failed = PropertyVerdictValue(Verdict.FAIL, "Failed")
    ignored = PropertyVerdictValue(Verdict.IGNORE, "test reason")

    for label, expected in [("test-type", ignored), ("other-type", failed)]:
        evidence = Evidence(EvidenceSource("Source", label=label))

        event = PropertyEvent(evidence, device.entity, (key, failed))
        inspector.property_update(event)
        assert event.key_value == (key, expected)

        address_event = PropertyAddressEvent(evidence, IPAddress.new("1.2.3.4"), (key, failed))
        inspector.property_address_update(address_event)
        assert address_event.key_value == (key, expected)
