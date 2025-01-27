"""IgnoreRules definition"""
from dataclasses import dataclass
from typing import List, Dict, Union, Tuple, Optional

from toolsaf.common.entity import Entity
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey, PropertyVerdictValue


@dataclass
class IgnoreRule:
    """Data class representing a single rule"""
    tool: str
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

    def tool(self, name: str) -> None:
        """Set tool that result applies to"""
        self._current_rule = IgnoreRule(name, [], [])
        if name not in self.rules:
            self.rules[name] = []
        self.rules[name] += [self._current_rule]

    def results(self, *results: Tuple[str, ...]) -> None:
        """Set result keys that rule applies to"""
        assert self._current_rule, "Call tool() first"
        for result in results:
            self._current_rule.results.append(PropertyKey(*result))

    def at(self, location: Entity) -> None:
        """Set location to which the rules apply to"""
        assert self._current_rule, "Call tool() first"
        self._current_rule.at.append(location)

    def reason(self, explanation: str) -> None:
        """Give reason for the ignore rule"""
        assert self._current_rule, "Call tool() first"
        self._current_rule.explanation = explanation

    def reset_current_rule(self) -> None:
        """Reset current rule"""
        self._current_rule = None

    def update_based_on_rules(self, file_type: str, key: PropertyKey,
            prop_set_value: PropertyVerdictValue, at: Entity) -> None:
        """Update given propertys verdict and explanation at given location"""
        for rule in self.rules.get(file_type, []):
            if (key in rule.results or not rule.results) and (not rule.at or at in rule.at):
                prop_set_value.verdict = Verdict.IGNORE
                if rule.explanation:
                    prop_set_value.explanation = rule.explanation
                break
