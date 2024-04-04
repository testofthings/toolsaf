import enum
from typing import List, Dict, Tuple, Optional

from tcsfw.basics import Verdict

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
