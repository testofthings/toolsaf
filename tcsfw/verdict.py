import enum
from typing import List, Dict, Tuple, Optional

from tcsfw.address import AnyAddress
from tcsfw.traffic import Event, Flow

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

class Verdictable:
    """Base class for objects with verdict"""
    def get_verdict(self) -> Verdict:
        raise NotImplementedError()


class Status(enum.Enum):
    """Entity status"""
    PLACEHOLDER = "Placeholder"    # Placeholder for unexpected or external entity
    EXPECTED = "Expected"          # Expected entity
    UNEXPECTED = "Unexpected"      # Unexpected entity
    EXTERNAL = "External"          # External entity
