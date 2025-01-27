"""IgnoreRules definition"""
from dataclasses import dataclass
from typing import List, Dict, Union, Tuple, Optional

from toolsaf.common.entity import Entity
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey, PropertyVerdictValue


@dataclass
class IgnoreRule:
    """Data class representing a single rule"""
    file_type: str
    results: List[PropertyKey]
    at: List[Entity]
    explanation: str=""

    def to_dict(self) -> Dict[PropertyKey, Dict[str, Union[List[Entity], str]]]:
        """Convert to dictionary"""
        return {key: {"at": self.at, "exp": self.explanation} for key in self.results}

    def __repr__(self) -> str:
        return f"IgnoreRule {self.tool}"


class IgnoreRules:
    """Rules for ignoring tool results"""
    def __init__(self) -> None:
        self.rules: Dict[str, List[IgnoreRule]] = {}
        self._current_rule: Optional[IgnoreRule] = None

    def new_rule(self, file_type: str) -> None:
        self._current_rule = IgnoreRule(file_type, [], [])
        if file_type not in self.rules:
            self.rules[file_type] = []
        self.rules[file_type] += [self._current_rule]

    def properties(self, *properties: Tuple[str, ...]) -> None:
        """Set properties that the rule applies to. Leave empty for all properties"""
        assert self._current_rule, "Call ignore() first"
        for result in properties:
            self._current_rule.results.append(PropertyKey.parse(result))

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
            if (key in rule.results or not rule.results) and (not rule.at or at in rule.at):
                prop_set_value.verdict = Verdict.IGNORE
                if rule.explanation:
                    prop_set_value.explanation = rule.explanation
                break
