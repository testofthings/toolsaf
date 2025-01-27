"""IgnoreRules definition"""
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

from toolsaf.common.entity import Entity
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey, PropertyVerdictValue


@dataclass
class IgnoreRule:
    """Data class representing a single rule"""
    file_type: str
    properties: List[PropertyKey]
    at: List[Entity]
    explanation: str=""

    def __repr__(self) -> str:
        return f"IgnoreRule {self.file_type}"


class IgnoreRules:
    """Rules for ignoring properties based on file type"""
    def __init__(self) -> None:
        self.rules: Dict[str, List[IgnoreRule]] = {}
        self._current_rule: Optional[IgnoreRule] = None

    def new_rule(self, file_type: str) -> None:
        self._current_rule = IgnoreRule(file_type, [], [])
        self.rules.setdefault(file_type, []).append(self._current_rule)

    def properties(self, *properties: Tuple[str, ...]) -> None:
        """Set properties that the rule applies to. Leave empty for all properties"""
        assert self._current_rule, "Call ignore() first"
        for result in properties:
            self._current_rule.properties.append(PropertyKey.parse(result))

    def at(self, location: Entity) -> None:
        """Set location to which the rules apply to"""
        assert self._current_rule, "Call ignore() first"
        self._current_rule.at.append(location)

    def because(self, explanation: str) -> None:
        """Give reason for the ignore rule"""
        assert self._current_rule, "Call ignore() first"
        self._current_rule.explanation = explanation

    def update_based_on_rules(self, file_type: str, key: PropertyKey,
            prop_set_value: PropertyVerdictValue, at: Entity) -> None:
        """Update given propertys verdict and explanation at given location"""
        for rule in self.rules.get(file_type, []):
            if (key in rule.properties or not rule.properties) and (not rule.at or at in rule.at):
                prop_set_value.verdict = Verdict.IGNORE
                if rule.explanation:
                    prop_set_value.explanation = rule.explanation
                return
