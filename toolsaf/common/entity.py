"""Base entity class and related classes"""

from typing import Dict, Optional, Self, List, Any, Tuple, Iterable, Iterator

from toolsaf.common.basics import Status
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.common.verdict import Verdictable
from toolsaf.common.address import AddressSequence, AnyAddress


class Entity:
    """An entity, network node or connection"""
    def __init__(self) -> None:
        self.concept_name = "other"
        self.status = Status.UNEXPECTED
        self.properties: Dict[PropertyKey, Any] = {}

    def long_name(self) -> str:
        """Get long name, possibly with spaces"""
        return self.concept_name

    def reset(self) -> None:
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

    def set_seen_now(self, changes: Optional[List['Entity']] = None) -> bool:
        """The entity is seen now, update and return if changes"""
        v = Properties.EXPECTED.get_verdict(self.properties)
        if self.status == Status.EXPECTED:
            if v == Verdict.PASS:
                return False  # already ok
            v = Verdict.PASS
        elif self.status == Status.UNEXPECTED:
            if v == Verdict.FAIL:
                return False  # already not ok
            v = Verdict.FAIL
        else:
            return False  # does not matter if seen or not
        self.set_property(Properties.EXPECTED.verdict(v))
        if changes is not None:
            changes.append(self)
        return True

    def get_expected_verdict(self, default: Optional[Verdict] = Verdict.INCON) -> Optional[Verdict]:
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

    def is_expected(self) -> bool:
        """Is an expected entity?"""
        return self.status == Status.EXPECTED

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

    def iterate(self, relevant_only: bool=True) -> Iterator['Entity']:
        """Iterate this and all child entities"""
        if not relevant_only or self.is_relevant():
            yield self
        for c in self.get_children():
            yield from c.iterate(relevant_only)

    def status_verdict(self) -> Tuple[Status, Optional[Verdict]]:
        """Get status and expected verdict"""
        return self.status, self.get_expected_verdict()

    def status_string(self, cache: Optional[Dict['Entity', Verdict]]=None) -> str:
        """Get a status string"""
        st = self.status.value
        v = self.get_verdict(cache if cache else {})
        if v is not None and v is not Verdict.INCON:
            st = f"{st}/{v.value}"
        return st

    def get_system_address(self) -> AddressSequence:
        """Get system address for this entity"""
        return AddressSequence.new()

    def find_entity(self, address: AnyAddress) -> Optional['Entity']:
        """Find an entity by address"""
        if isinstance(address, AddressSequence):
            if not address.segments:
                return self
        raise NotImplementedError()

    def __repr__(self) -> str:
        s = f"{self.status_string()} {self.long_name()}"
        return s
