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
    def resolve(cls, *verdicts: Optional['Verdict']) -> 'Verdict':
        """Resolve verdict when new information accumulates during inspection"""
        vs = [v for v in verdicts if v]
        if not vs:
            return Verdict.INCON
        if len(vs) == 1:
            return vs[0]
        v_set = set(vs)
        for s in (Verdict.FAIL, Verdict.PASS, Verdict.IGNORE, Verdict.INCON):
            if s in v_set:
                return s
        raise NotImplementedError(f"Merging of {verdicts}")

    @classmethod
    def aggregate(cls, *verdicts: Optional['Verdict']) -> 'Verdict':
        """Resolve verdict aggregating sub-verdicts"""
        return cls.resolve(*verdicts)

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
