"""IgnoreRules definition"""
from dataclasses import dataclass
from typing import List, Dict, Union, Tuple, Optional

from toolsaf.common.entity import Entity
from toolsaf.common.property import PropertyKey
from toolsaf.core.model import Addressable


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

    def should_ignore(self, tool: str, key: PropertyKey, at: Optional[Addressable]) \
            -> Tuple[bool, str]:
        """Check if given key should be ignored at given location.
           Also returns an explanation that may be empty"""
        for rule in self.rules.get(tool, []):
            if (key in rule.results or not rule.results) and (not rule.at or at in rule.at):
                return True, rule.explanation
        return False, ""
