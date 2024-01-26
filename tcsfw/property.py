from dataclasses import dataclass
from typing import Set, Dict, Any, Optional, Tuple, TypeVar, Generic, Self

from tcsfw.verdict import Verdict, Verdictable

# Property value type
V = TypeVar("V")


class PropertyKey(Generic[V]):
    """Property key"""
    def __init__(self, name: str, *more: str):
        """Create new property key"""
        self.segments: Tuple[str, ...] = name, *more
        self.model = False  # a model property?

    def append_key(self, segment: str) -> Self:
        """Add key segment"""
        return self.create(self.segments + (segment, ))

    def prefix_key(self, segment: str, append="") -> Self:
        """Re-prefix key segment, with possibly also adding a key segment"""
        assert len(self.segments) > 1, "At least two-segment key required to change prefix"
        return self.create((segment, ) + self.segments[1:] + ((append, ) if append else ()))

    @classmethod
    def create(cls, name: Tuple[str, ...]) -> 'PropertyKey':
        """Create new property key"""
        assert len(name) > 0, "No name segments"
        return PropertyKey(name[0], *name[1:])

    @classmethod
    def parse(cls, name_segments: str) -> 'PropertyKey':
        """Parse name segments into a key"""
        return cls.create(tuple(name_segments.split(":")))

    def reset(self, value: V) -> Optional[V]:
        """Reset the value, return None to remove"""
        return None

    def get_name(self, short=False) -> str:
        """Name string"""
        if short:
            return self.segments[-1]
        return ":".join(self.segments)

    def new(self, value: V) -> Tuple['PropertyKey', V]:
        """New key ana value """
        return self, value

    def set(self, properties: 'PropertyDict', value: V) -> V:
        """New key ana value """
        properties[self] = value
        return self, value

    def get(self, properties: 'PropertyDict') -> Optional[V]:
        """Get the set from properties or null"""
        v = properties.get(self)
        return v

    def get_explanation(self, value: V) -> str:
        """Get explanation for value, if any"""
        return ""

    def get_value_string(self, value: V) -> str:
        """Get value as string"""
        value_s = f"{value}"
        return f"{self.get_name()}={value_s}" if value_s else self.get_name()

    def update(self, properties: 'PropertyDict', value: V):
        """Update existing property dictionary with new value"""
        properties[self] = value

    def __hash__(self):
        return self.segments.__hash__()

    def __eq__(self, other):
        if not isinstance(other, PropertyKey):
            return False
        return self.segments == other.segments

    def __gt__(self, other):
        return self.segments.__gt__(other.segments)

    def __repr__(self):
        return self.get_name()


# Property dictionary
PropertyDict = Dict[PropertyKey, Any]


@dataclass
class PropertyVerdictValue(Verdictable):
    """Property verdict value"""
    verdict: Verdict
    explanation: str

    def get_verdict(self) -> Verdict:
        return self.verdict

    def __repr__(self):
        s = f" {self.explanation}" if self.explanation else ""
        return f"[{self.verdict.value}]{s}"


class PropertyVerdict(PropertyKey[PropertyVerdictValue]):
    """Verdict and explanation as property value"""
    def __init__(self, key: str, *more: str):
        super().__init__(key, *more)

    @classmethod
    def create(cls, name: Tuple[str, ...]) -> 'PropertyVerdict':
        """Create new property key"""
        return PropertyVerdict(name[0], *name[1:])

    def persistent(self) -> Self:
        """Make a persistent property"""
        self.model = True
        return self

    def reset(self, value: PropertyVerdictValue) -> Optional[PropertyVerdictValue]:
        if self.model:
            return PropertyVerdictValue(Verdict.INCON, value.explanation)
        return None

    def value(self, verdict=Verdict.INCON, explanation="") -> Tuple['PropertyVerdict', PropertyVerdictValue]:
        """New property value"""
        return self, PropertyVerdictValue(verdict, explanation)

    def update(self, properties: PropertyDict, value: PropertyVerdictValue):
        assert isinstance(value, PropertyVerdictValue) and isinstance(value.verdict, Verdict), \
            f"Invalid property verdict value: {value}"
        old = self.get(properties)
        if old:
            if old.verdict == Verdict.IGNORE:
                use_new = False  # ignore is sticky
            elif old.verdict == Verdict.INCON:
                use_new = True  # maybe we have a conclusion
            else:
                use_new = value.verdict in {Verdict.IGNORE, Verdict.FAIL}
            if use_new:
                value = PropertyVerdictValue(value.verdict, value.explanation or old.explanation)
            else:
                value = PropertyVerdictValue(old.verdict, old.explanation or value.explanation)
        # use 'this' key even with old value, as old may have wrong key type
        properties[self] = value

    def get_value_string(self, value: PropertyVerdictValue) -> str:
        return f"{self.get_name()}={value.verdict.value}"

    def get_verdict(self, properties: PropertyDict) -> Optional[Verdict]:
        """Get the verdict, if any, not verdict value objects"""
        v = properties.get(self)
        return v.get_verdict() if v is not None else None

    def get_explanation(self, value: PropertyVerdictValue) -> str:
        return value.explanation

    @classmethod
    def cast(cls, key_value: Tuple[PropertyKey, Any]) -> Optional[PropertyVerdictValue]:
        """Cast to property set, if such given"""
        if not isinstance(key_value[0], PropertyVerdict):
            return None
        value = key_value[1]
        assert isinstance(value, PropertyVerdictValue)
        return value


@dataclass
class PropertySetValue:
    sub_keys: Set[PropertyKey]
    explanation: str = ""

    def get_overall_verdict(self, properties: PropertyDict) -> Verdict:
        """Get overall verdict for this"""
        v = None
        for k in self.sub_keys:
            value = properties.get(k)
            if isinstance(value, Verdictable):
                v = Verdict.aggregate(v, value.get_verdict())
            elif isinstance(value, PropertySetValue):
                sv = value.get_overall_verdict(properties)
                v = Verdict.aggregate(v, sv)
        if v is None or v == Verdict.IGNORE:
            v = Verdict.PASS  # no verdicts is pass
        return v


class PropertySet(PropertyKey):
    """Property set"""
    def __init__(self, key: str, *more: str):
        super().__init__(key, *more)

    @classmethod
    def create(cls, name: Tuple[str, ...]) -> 'PropertyKey':
        """Create new property key"""
        return PropertySet(name[0], *name[1:])

    def value(self, sub_keys: Set[PropertyKey], explanation="") -> Tuple[PropertyKey, PropertySetValue]:
        """Create new key and value pair"""
        return self, PropertySetValue(sub_keys, explanation)

    def get(self, properties: PropertyDict) -> Optional[PropertySetValue]:
        v = properties.get(self)
        assert v is None or isinstance(v, PropertySetValue), f"Not a property key {v}"
        return v

    def update(self, properties: PropertyDict, value):
        """Update existing property dictionary with set values"""
        assert isinstance(value, PropertySetValue)
        old = self.get(properties)
        if old:
            old.sub_keys.update(value.sub_keys)
            properties[self] = old
        else:
            properties[self] = value

    def get_overall_verdict(self, properties: PropertyDict) -> Verdict:
        """Get overall verdict for this set or NOT SEEN"""
        v = None
        p_set = self.get(properties)
        if p_set is None:
            return Verdict.INCON  # not seen
        return p_set.get_overall_verdict(properties)

    def get_value_string(self, value: PropertySetValue) -> str:
        v = f"{value.get_overall_verdict({})}" if not value.sub_keys else f"{value.sub_keys}"
        return f"{self.get_name()}={v}"

    def get_explanation(self, value: PropertySetValue) -> str:
        return value.explanation

    @classmethod
    def cast(cls, key_value: Tuple[PropertyKey, Any]) -> Optional[PropertySetValue]:
        """Cast to property set, if such given"""
        if not isinstance(key_value[0], PropertySet):
            return None
        value = key_value[1]
        assert isinstance(value, PropertySetValue)
        return value


class Properties:
    AUTHENTICATION = PropertySet("check", "auth")    # Authentication check
    AUTH_BEST_PRACTICE = AUTHENTICATION.append_key("best-practice")  # Auth. crypto best practise
    AUTH_NO_VULNERABILITIES = AUTHENTICATION.append_key("no-vulnz")  # Auth. known vulnerabilities
    AUTH_BRUTE_FORCE = AUTHENTICATION.append_key("brute-force")  # Auth. brute force
    AUTHENTICATION_DATA = PropertyVerdict("default", "auth").persistent()   # Data used in authentication
    AUTHENTICATION_GRANT = PropertySet("check", "auth", "grant")    # Authentication granted/rejected check
    NO_AUTHENTICATION = PropertySet("check", "no-auth")    # No authentication
    PROTOCOL = PropertySet("check", "protocol")      # Protocol-specific check, augment with protocol name
    WEB_BEST = PropertySet("check", "web")           # Web best practices, HTTP/TLS covered by PROTOCOL
    ENCRYPTION = PropertySet("check", "encryption")  # Encryption best practices
    EXPECTED = PropertyVerdict("check", "expected")  # Entry is expected (True) or unexpected (False)
    COOKIES = PropertySet("check", "cookies")        # Cookies checks
    COMPONENTS = PropertySet("check", "components")  # Software component check
    VULNERABILITIES = PropertySet("check", "vulnz")  # Component vulnerability check
    CODE_REVIEW = PropertySet("check", "code-review")   # Source code review
    CODE_SCA = PropertySet("check", "sca")           # Software composition analysis (SCA)
    PERMISSIONS = PropertySet("check", "permissions")  # Permission check
    UI = PropertySet("check", "ui")                   # User interface check
    PHYSICAL = PropertySet("check", "physical")       # Physical manipulation or checks
    DOCUMENT_AVAILABILITY = PropertyVerdict("check", "avail")  # Document, web-page, etc. availabilty check
    DOCUMENT_CONTENT = PropertySet("check", "content")           # Document, web-page, etc. content check
    FUZZ = PropertySet("check", "fuzz")              # Fuzz testing!
    DATA_CONFIRMED = PropertySet("check", "data")    # Presence of data confirmed
    HTTP_REDIRECT = PropertyVerdict("default", "http-redirect").persistent()  # HTTP redirect detected
    MITM = PropertyVerdict("check", "mitm")        # MITM successful?
    EXPECTED_HOSTS = PropertyKey("check", "hosts")  # Expected entity is observed
    EXPECTED_SERVICES = PropertyKey("check", "services")  # Expected entity is observed
    EXPECTED_CONNECTIONS = PropertyKey("check", "connections")  # Expected entity is observed
    UPDATE_SEEN = PropertyKey("default", "update-seen")            # Update is seen
    REVIEW = PropertyKey("check", "review")         # IXIT etc. review
    FUNCTIONAL = PropertyKey("other", "functional")

    @classmethod
    def get_flags(cls, properties: Dict[PropertyKey, Any]) -> Set[str]:
        """Get flag strings"""
        flags = set()
        if cls.UI in properties:
            flags.add("ui")
        if cls.PHYSICAL in properties:
            flags.add("physic")
        if cls.DOCUMENT_CONTENT in properties:
            flags.add("doc")
        if cls.REVIEW in properties:
            flags.add("rev")
        return flags
