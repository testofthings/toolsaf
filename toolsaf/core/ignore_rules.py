"""IgnoreRules definition"""
from dataclasses import dataclass
from typing import Set, List, Dict, Tuple, Optional, cast

from toolsaf.common.entity import Entity
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey, PropertyVerdictValue


@dataclass
class IgnoreRule:
    """Data class representing a single rule"""
    file_type: str
    properties: Set[PropertyKey]
    at: Set[str]
    explanation: str=""

    def __repr__(self) -> str:
        return f"IgnoreRule {self.file_type}"


class IgnoreRules:
    """Rules for ignoring properties based on file type"""
    def __init__(self) -> None:
        self.rules: Dict[str, List[IgnoreRule]] = {}
        self._current_rule: Optional[IgnoreRule] = None

    def new_rule(self, file_type: str) -> None:
        """Create a new rule"""
        self._current_rule = IgnoreRule(file_type, set(), set())
        self.rules.setdefault(file_type, []).append(self._current_rule)

    def properties(self, *properties: Tuple[str, ...]) -> None:
        """Set properties that the rule applies to. Leave empty for all properties"""
        assert self._current_rule, "Call ignore() first"
        for entry in properties:
            self._current_rule.properties.add(
                PropertyKey.parse(cast(str, entry))
            )

    def at(self, location: Entity) -> None:
        """Set location to which the rules apply to"""
        assert self._current_rule, "Call ignore() first"
        self._current_rule.at.add(location.get_system_address().get_parseable_value())

    def because(self, explanation: str) -> None:
        """Give reason for the ignore rule"""
        assert self._current_rule, "Call ignore() first"
        self._current_rule.explanation = explanation

    def update_based_on_rules(self, file_type: str, key: PropertyKey,
            verdict_value: PropertyVerdictValue, at: Entity) -> PropertyVerdictValue:
        """Update given propertys verdict and explanation at given location"""
        at_address = at.get_system_address().get_parseable_value()
        for rule in self.rules.get(file_type, []):
            if (key in rule.properties or not rule.properties) and (not rule.at or at_address in rule.at):
                new_pvv = PropertyVerdictValue(
                    Verdict.IGNORE, explanation=rule.explanation if rule.explanation else verdict_value.explanation
                )
                return new_pvv
        return verdict_value
