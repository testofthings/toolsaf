"""Base entity class and related classes"""

import enum
import re
from typing import Dict, Optional, Self, List, Any, Tuple, Iterable, Iterator
from tcsfw.basics import Status
from tcsfw.verdict import Verdict

from tcsfw.claim import AbstractClaim
from tcsfw.property import Properties, PropertyKey
from tcsfw.verdict import Verdictable


class Entity:
    """An entity, network node or connection"""
    def __init__(self):
        self.concept_name = "other"
        self.status = Status.UNEXPECTED
        self.properties: Dict[PropertyKey, Any] = {}

    def long_name(self) -> str:
        """Get long name, possibly with spaces"""
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
            if v == Verdict.PASS:
                v = self.get_expected_verdict()  # expected has veto
            cache[self] = v = v or Verdict.INCON
        return v

    def is_relevant(self) -> bool:
        """Is this entity relevant, i.e. not placeholder or external?"""
        return True

    def is_admin(self) -> bool:
        """Is an admin entity?"""
        return False

    def is_host(self) -> bool:
        """Is a host?"""
        return False

    def is_service(self) -> bool:
        """Is a service?"""
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
    """Status of a claim"""
    def __init__(self, claim: AbstractClaim, explanation="", verdict=Verdict.INCON, authority=ClaimAuthority.MODEL):
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


class ExplainableClaim(AbstractClaim):
    """A claim which can be explained, with or without status"""
    def explain(self, status: Optional[ClaimStatus]) -> str:
        """Explain the claim and status. Status can be null"""
        if status and status.explanation:
            return status.explanation
        return str(self)


class SafeNameMap:
    """Safe names for entities"""
    def __init__(self, prefix = ""):
        self.prefix = prefix
        self.safe_names: Dict[Any, str] = {}
        self.reverse_map: Dict[str, Any] = {}

    def get_safe_name(self, entity: Entity) -> str:
        """Get safe name for an entity to use in file names, variables, etc."""
        sn = self.safe_names.get(entity)
        if sn is None:
            sn = self.prefix + self.replace_non_alphanumeric(entity.long_name())
            self.safe_names[entity] = sn
            self.reverse_map[sn] = entity
        elif self.reverse_map.get(sn) != entity:
            raise ValueError(f"Safe name collision: {sn} for {entity} and {self.reverse_map[sn]}")
        return sn

    def get_env_name(self, entity: Entity) -> str:
        """Get environment variable name for an entity"""
        sn = self.get_safe_name(entity).upper()
        if sn not in self.reverse_map:
            self.reverse_map[sn] = entity
        elif self.reverse_map[sn] != entity:
            raise ValueError(f"Safe name collision: {sn} for {entity} and {self.reverse_map[sn]}")
        return sn

    @classmethod
    def replace_non_alphanumeric(cls, string):
        """Replace any character that is NOT alphanumeric or underscore with an underscore"""
        s = re.sub(r'[^a-zA-Z0-9_]', '_', string)
        s = re.sub(r'_+', '_', s)  # repeated _:s
        if s and '0' <= s[0] <= '9':
            s = f"_{s}"
        return s
