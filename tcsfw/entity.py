import enum
from typing import Dict, Optional, Self, List, Any, Tuple, Iterable, Callable, Iterator, TypeVar

from tcsfw.claim import Claim
from tcsfw.property import Properties, PropertyKey
from tcsfw.verdict import Status, Verdict, Verdictable


class Entity:
    """An entity, network node or connection"""
    def __init__(self):
        self.concept_name = "other"
        self.status = Status.UNEXPECTED
        self.properties: Dict[PropertyKey, Any] = {}

    def long_name(self) -> str:
        return self.concept_name

    def reset(self):
        """Reset entity and at least properties"""
        new_p: Dict[PropertyKey, Any] = {}
        for k, v in self.properties.items():
            nv = k.reset(v)
            if nv is not None:
                new_p[k] = nv  # keep a property
        self.properties = new_p

    def set_property(self, key_value: Tuple[PropertyKey, Any]) -> Self:
        """Set a property"""
        self.properties[key_value[0]] = key_value[1]
        return self

    def set_seen_now(self, changes: List['Entity'] = None) -> bool:
        """The entity is seen now, update and return if changes"""
        v = Properties.EXPECTED.get_verdict(self.properties)
        if self.status == Status.EXPECTED: 
            if v == Verdict.PASS:
                return False  # already ok
            v = Verdict.PASS
        elif self.status == Status.UNEXPECTED:
            if v == Verdict.FAIL:
                return None  # already not ok
            v = Verdict.FAIL
        else:
            return False  # does not matter if seen or not
        self.set_property(Properties.EXPECTED.verdict(v))
        if changes is not None:
            changes.append(self)
        return True

    def get_expected_verdict(self, default: Optional[Verdict] = Verdict.INCON) -> Verdict:
        """Get the expected verdict or undefined"""
        return Properties.EXPECTED.get_verdict(self.properties) or default

    def get_children(self) -> Iterable['Entity']:
        """Get child entities, if any"""
        return ()

    def get_verdict(self, cache: Dict['Entity', Verdict]) -> Verdict:
        """Get aggregate verdict"""
        v = cache.get(self)
        if v is None:
            for c in self.get_children():
                v = Verdict.aggregate(v, c.get_verdict(cache))
            for p in self.properties.values():
                v = Verdict.aggregate(v, p.get_verdict()) if isinstance(p, Verdictable) else v
            cache[self] = v = v or Verdict.INCON
        return v

    def is_relevant(self) -> bool:
        """Is this entity relevant, i.e. not placeholder or external?"""
        return True

    def is_host(self) -> bool:
        """Is a host?"""
        return False

    def is_host_reachable(self) -> bool:
        """Are hosts reachable from here"""
        return False

    def iterate(self, relevant_only=True) -> Iterator['Entity']:
        """Iterate this and all child entities"""
        if not relevant_only or self.is_relevant():
            yield self
        for c in self.get_children():
            yield from c.iterate(relevant_only)

    def status_verdict(self) -> Tuple[Status, Verdict]:
        """Get status and expected verdict"""
        return self.status, self.get_expected_verdict()

    def status_string(self) -> str:
        """Get a status string"""
        st = self.status.value
        v = Properties.EXPECTED.get_verdict(self.properties)
        if v is not None:
            st = f"{st}/{v.value}"
        return st

    def __repr__(self):
        s = f"{self.status_string()} {self.long_name()}"
        return s

class ClaimAuthority(enum.Enum):
    """Claim or claim status authority"""
    MODEL = "Model"          # Model claim, inferred from model
    TOOL = "Tool"            # Tool verified claim
    MANUAL = "Manual"        # Manually verified claim


class ClaimStatus:
    def __init__(self, claim: Claim, explanation="", verdict=Verdict.INCON, authority=ClaimAuthority.MODEL):
        assert claim is not None and verdict is not None
        self.claim = claim
        self.verdict = verdict
        self.explanation = explanation
        self.authority = authority
        self.silent = False
        self.aggregate_of: List[ClaimStatus] = []

    def get_explanation(self) -> str:
        """Get explanation"""
        if isinstance(self.claim, ExplainableClaim):
            return self.claim.explain(self)
        return self.claim.text()

    def __repr__(self) -> str:
        return f"{self.verdict.value} {self.get_explanation()}"


class ExplainableClaim(Claim):
    """A claim which can be explained, with or without status"""
    def explain(self, status: Optional[ClaimStatus]) -> str:
        """Explain the claim and status. Status can be null"""
        if status and status.explanation:
            return status.explanation
        return self.__repr__()

