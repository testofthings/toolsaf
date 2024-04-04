from dataclasses import dataclass
from typing import Set, Dict, Any, Optional, Tuple, TypeVar, Generic, Self
from tcsfw.basics import Verdict

from tcsfw.verdict import Verdictable

class PropertyKey:
    """Property key"""
    def __init__(self, name: str, *more: str):
        """Create new property key"""
        self.segments: Tuple[str, ...] = name, *more
        self.model = False  # a model property?

    def persistent(self) -> Self:
        """Make a persistent property"""
        self.model = True
        return self

    def is_protected(self) -> bool:
        """Is this a protected property?"""
        return self.segments[0] in Properties.PROTECTED

    def append_key(self, segment: str) -> Self:
        """Add key segment"""
        return self.create(self.segments + (segment, ))

    def prefix_key(self, segment: str, append="") -> Self:
        """Prefix key segment, with possibly also adding a key segment"""
        return self.create((segment, ) + self.segments + ((append, ) if append else ()))

    @classmethod
    def create(cls, name: Tuple[str, ...]) -> 'PropertyKey':
        """Create new property key"""
        assert len(name) > 0, "No name segments"
        return PropertyKey(name[0], *name[1:])

    @classmethod
    def parse(cls, name_segments: str) -> 'PropertyKey':
        """Parse name segments into a key"""
        return cls.create(tuple(name_segments.split(":")))

    def reset(self, value: Any) -> Optional[Any]:
        """Reset the value, return None to remove"""
        if self.model:
            return PropertyVerdictValue(Verdict.INCON) if isinstance(value, PropertyVerdictValue) else value
        return None

    def get_name(self, short=False) -> str:
        """Name string"""
        if short:
            return self.segments[-1]
        return ":".join(self.segments)

    def set(self, properties: 'PropertyDict', value: Any) -> Any:
        """New key and value """
        properties[self] = value
        return self, value

    def get(self, properties: 'PropertyDict') -> Optional[Any]:
        """Get the set from properties or null"""
        v = properties.get(self)
        return v

    def get_explanation(self, value: Any) -> str:
        """Get explanation for value, if any"""
        if isinstance(value, PropertyVerdictValue):
            return value.explanation
        elif isinstance(value, PropertySetValue):
            return value.explanation
        return ""

    def update(self, properties: 'PropertyDict', value: Any):
        """Update existing property dictionary with new value"""
        if isinstance(value, PropertyVerdictValue):
            self.update_verdict(properties, value)
        elif isinstance(value, PropertySetValue):
            self.update_set(properties, value)
        else:
            # simple override
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

    def get_value_string(self, value: Any) -> str:
        """Get value as string"""
        if isinstance(value, PropertyVerdictValue):
            s = value.verdict.value
        elif isinstance(value, PropertySetValue):
            s = f"{value.get_overall_verdict({})}" if not value.sub_keys else f"{value.sub_keys}"
        else:
            s = f"{value}"
        return f"{self.get_name()}={s}" if s else self.get_name()

    def get_value_json(self, value: Any, json_data: Dict) -> Dict:
        """Get value as JSON"""
        if isinstance(value, PropertyVerdictValue):
            json_data["verdict"] = value.verdict.value
            if value.explanation:
                json_data["exp"] = value.explanation
        elif isinstance(value, PropertySetValue):
            json_data["set"] = [k.get_name() for k in value.sub_keys]
            if value.explanation:
                json_data["exp"] = value.explanation
        else:
            json_data["value"] = f"{value}"
        return json_data

    def decode_value_json(self, data: Dict) -> Any:
        """Decode value from JSON"""
        exp = data.get("exp", "")
        if "verdict" in data:
            return PropertyVerdictValue(Verdict.parse(data["verdict"]), exp)
        if "set" in data:
            return PropertySetValue({PropertyKey.parse(k) for k in data["set"]}, exp)
        return data.get("value")

    #
    # Verdict value
    #

    def verdict(self, verdict=Verdict.INCON, explanation="") -> Tuple['PropertyKey', 'PropertyVerdictValue']:
        """New key and verdict value """
        assert isinstance(verdict, Verdict)
        return self, PropertyVerdictValue(verdict, explanation)

    def put_verdict(self, properties: 'PropertyDict', verdict=Verdict.INCON,
                    explanation="") -> Tuple['PropertyKey', 'PropertyVerdictValue']:
        """Set verdict value"""
        kv = PropertyVerdictValue(verdict, explanation)
        properties[self] = kv
        return self, kv

    def get_verdict(self, properties: 'PropertyDict') -> Optional[Verdict]:
        """Get the verdict, if any, not verdict value objects"""
        v = properties.get(self)
        if isinstance(v, PropertySetValue):
            return v.get_overall_verdict(properties)
        return v.get_verdict() if isinstance(v, Verdictable) else None

    def update_verdict(self, properties: 'PropertyDict', value: 'PropertyVerdictValue'):
        assert isinstance(value, PropertyVerdictValue) and isinstance(value.verdict, Verdict), \
            f"Invalid property verdict value: {value}"
        old = self.get(properties)
        if isinstance(old, PropertyVerdictValue):
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
        properties[self] = value

    #
    # Set value
    #

    def value_set(self, sub_keys: Set['PropertyKey'], explanation="") -> Tuple['PropertyKey', 'PropertySetValue']:
        """New property set value"""
        return self, PropertySetValue(sub_keys, explanation)

    def get_set(self, properties: 'PropertyDict') -> Optional['PropertySetValue']:
        """Get property set value, if available"""
        v = properties.get(self)
        return v if isinstance(v, PropertySetValue) else None

    def update_set(self, properties: 'PropertyDict', value: 'PropertySetValue'):
        """Update existing property dictionary with set values"""
        assert isinstance(value, PropertySetValue)
        old = self.get(properties)
        if isinstance(old, PropertySetValue):
            v = old.sub_keys.copy()
            v.update(value.sub_keys)
            properties[self] = v
        elif isinstance(old, PropertyVerdictValue) and old.verdict == Verdict.IGNORE:
            # ignore is sticky
            return
        else:
            properties[self] = value


# Property dictionary
PropertyDict = Dict[PropertyKey, Any]


@dataclass
class PropertyVerdictValue(Verdictable):
    """Property verdict value"""
    verdict: Verdict
    explanation: str = ""

    def get_verdict(self) -> Verdict:
        return self.verdict

    def __repr__(self):
        s = f" {self.explanation}" if self.explanation else ""
        return f"[{self.verdict.value}]{s}"

    def __hash__(self) -> int:
        return self.verdict.__hash__() ^ self.explanation.__hash__()

    def __eq__(self, v) -> bool:
        if not isinstance(v, PropertyVerdictValue):
            return False
        return self.verdict == v.verdict and self.explanation == v.explanation


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
                kv = value.get_verdict()
                if kv is None or kv == Verdict.IGNORE:
                    continue
                v = Verdict.aggregate(v, kv)
            elif isinstance(value, PropertySetValue):
                kv = value.get_overall_verdict(properties)
                if kv is None or kv == Verdict.IGNORE:
                    continue
                v = Verdict.aggregate(v, kv)
        if v is None or v == Verdict.IGNORE:
            v = Verdict.PASS  # no verdicts is pass
        return v

    def __hash__(self) -> int:
        return self.sub_keys.__hash__() ^ self.explanation.__hash__()

    def __eq__(self, v) -> bool:
        if not isinstance(v, PropertySetValue):
            return False
        return self.sub_keys() == v.sub_keys and self.explanation == v.explanation


class Properties:
    AUTHENTICATION = PropertyKey("check", "auth")    # Authentication check
    AUTH_BEST_PRACTICE = AUTHENTICATION.append_key("best-practice")  # Auth. crypto best practise
    AUTH_NO_VULNERABILITIES = AUTHENTICATION.append_key("no-vulnz")  # Auth. known vulnerabilities
    AUTH_BRUTE_FORCE = AUTHENTICATION.append_key("brute-force")  # Auth. brute force
    AUTHENTICATION_GRANT = PropertyKey("check", "auth", "grant")    # Authentication granted/rejected check
    NO_AUTHENTICATION = PropertyKey("check", "no-auth")    # No authentication
    PROTOCOL = PropertyKey("check", "protocol")      # Protocol-specific check, augment with protocol name
    WEB_BEST = PropertyKey("check", "web")           # Web best practices, HTTP/TLS covered by PROTOCOL
    ENCRYPTION = PropertyKey("check", "encryption")  # Encryption best practices
    EXPECTED = PropertyKey("check", "expected")      # Entry is expected (True) or unexpected (False)
    COOKIES = PropertyKey("check", "cookies")        # Cookies checks
    COMPONENTS = PropertyKey("check", "components")  # Software component check
    VULNERABILITIES = PropertyKey("check", "vulnz")  # Component vulnerability check
    CODE_REVIEW = PropertyKey("check", "code-review")  # Source code review
    CODE_SCA = PropertyKey("check", "sca")           # Software composition analysis (SCA)
    PERMISSIONS = PropertyKey("check", "permissions")  # Permission check
    UI = PropertyKey("check", "ui")                  # User interface check
    PHYSICAL = PropertyKey("check", "physical")      # Physical manipulation or checks
    DOCUMENT_AVAILABILITY = PropertyKey("check", "avail")  # Document, web-page, etc. availabilty check
    DOCUMENT_CONTENT = PropertyKey("check", "content") # Document, web-page, etc. content check
    FUZZ = PropertyKey("check", "fuzz")              # Fuzz testing!
    DATA_CONFIRMED = PropertyKey("check", "data")    # Presence of data confirmed
    HTTP_REDIRECT = PropertyKey("default", "http-redirect").persistent()  # HTTP redirect detected
    SENSORS = PropertyKey("default", "sensors").persistent()  # Has sensors
    MITM = PropertyKey("check", "mitm")              # MITM successful?
    UPDATE_SEEN = PropertyKey("check", "update-seen")  # Update is seen
    REVIEW = PropertyKey("check", "review")          # IXIT etc. review
    FUNCTIONAL = PropertyKey("other", "functional")

    # Property prefixes protected from manual set
    PROTECTED = {"check"}

    # Manual override prefix
    PREFIX_MANUAL = "manual"

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
