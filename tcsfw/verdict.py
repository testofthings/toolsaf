import enum
from typing import List, Dict, Tuple, Optional

from tcsfw.address import AnyAddress
from tcsfw.basics import Verdict
from tcsfw.traffic import Event, Flow

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
