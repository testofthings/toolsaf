import enum
from typing import Optional


class HostType(enum.Enum):
    """Host types"""
    GENERIC = ""               # default, assumed plaintext data
    DEVICE = "Device"          # local device
    MOBILE = "Mobile"          # mobile (application)
    REMOTE = "Remote"          # remote, youngsters call it "cloud"
    BROWSER = "Browser"        # browser, user selected and installed
    ADMINISTRATIVE = "Admin"   # administration, match ConnectionType


class ConnectionType(enum.Enum):
    """Connection types"""
    UNKNOWN = ""               # default, assumed plaintext data
    ENCRYPTED = "Encrypted"    # strong encryption
    ADMINISTRATIVE = "Admin"   # administration, no private data
    LOGICAL = "Logical"        # only a logical connection


class ExternalActivity(enum.IntEnum):
    """External activity levels"""
    BANNED = 0                 # no external activity allowed
    PASSIVE = 1                # passive, probing ok but no replies
    OPEN = 2                   # external use of open services ok
    UNLIMITED = 3              # unlimited activity, including client connections


class Verdict(enum.Enum):
    """Verdict for entity, connection, property, etc."""
    INCON = "Incon"                # Inconclusive check
    FAIL = "Fail"                  # Failed check
    PASS = "Pass"                  # All checks pass
    IGNORE = "Ignore"              # Ignore

    @classmethod
    def update(cls, *verdicts: 'Verdict') -> 'Verdict':
        """Update verdict for property, etc. Ignore overrides all others."""
        if not verdicts:
            return Verdict.INCON
        if len(verdicts) == 1:
            return verdicts[0]
        v_set = set(verdicts)
        for s in [Verdict.IGNORE, Verdict.FAIL, Verdict.PASS, Verdict.INCON]:
            if s in v_set:
                return s
        raise NotImplementedError(f"Cannot update {verdicts}")

    @classmethod
    def aggregate(cls, *verdicts: 'Verdict') -> 'Verdict':
        """Resolve aggregate verdict for entity from child verdicts, never return ignore."""
        if not verdicts:
            return Verdict.INCON
        v_set = set(verdicts)
        for s in [Verdict.FAIL, Verdict.PASS]:
            if s in v_set:
                return s
        return Verdict.INCON

    @classmethod
    def parse(cls, value: Optional[str]) -> 'Verdict':
        """Parse string to verdict"""
        if value is None:
            return cls.INCON
        v = Verdict_by_value.get(value.lower())
        if v is None:
            raise ValueError(f"Unknown verdict: {value}")
        return v


# Map verdicts to verdict values in lowercase
Verdict_by_value = {v.value.lower(): v for v in Verdict}
