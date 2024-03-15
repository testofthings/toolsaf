from typing import List
from tcsfw.requirement import Specification
from tcsfw.default_requirements import DEFAULT
from tcsfw.etsi_ts_103_701 import ETSI_TS_103_701, ETSI_TS_103_701_FIN


class Specifications:
    """Defined claim specifications"""
    _specifications: List[Specification] = {DEFAULT, ETSI_TS_103_701, ETSI_TS_103_701_FIN}

    @classmethod
    def get_specification(cls, specification="") -> Specification:
        """Get claim specification by label"""
        if not specification:
            return DEFAULT
        for s in cls._specifications:
            if s.specification_id == specification:
                return s
        raise ValueError(f"Unknown specification id '{specification}'")
