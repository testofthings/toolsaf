import enum
from typing import List, Iterable, Dict, Tuple, Optional

from tcsfw.address import AnyAddress
from tcsfw.traffic import Event, Flow


class Verdict(enum.Enum):
    """Verdict for entity, connection, etc."""
    UNDEFINED = "Undefined"        # Just created, unused, and/or left as placeholder after a reset
    NOT_SEEN = "Not seen"          # Not seen the item, so cannot draw conclusions
    UNEXPECTED = "Unexpected"      # Unexpected item
    MISSING = "Missing"            # Was missing when verified
    FAIL = "Fail"                  # Failed check
    PASS = "Pass"                  # All checks pass
    EXTERNAL = "External"          # External node or connection
    IGNORE = "Ignore"              # Ignore as false positive

    @classmethod
    def resolve(cls, *verdicts: Optional['Verdict']) -> 'Verdict':
        """Resolve verdict when new information accumulates during inspection"""
        vs = [v for v in verdicts if v]
        if not vs:
            return Verdict.UNDEFINED
        if len(vs) == 1:
            return vs[0]
        v_set = set(vs)
        for s in (Verdict.FAIL, Verdict.MISSING, Verdict.UNEXPECTED, Verdict.PASS, Verdict.EXTERNAL,
                  Verdict.NOT_SEEN, Verdict.IGNORE, Verdict.UNDEFINED):
            if s in v_set:
                return s
        raise NotImplementedError(f"Merging of {verdicts}")

    @classmethod
    def aggregate(cls, *verdicts: Optional['Verdict']) -> 'Verdict':
        """Resolve verdict aggregating sub-verdicts"""
        vs = [v for v in verdicts if v]
        if not vs:
            return Verdict.UNDEFINED
        if len(vs) == 1:
            return vs[0]
        v_set = set(vs)
        for s in (Verdict.FAIL, Verdict.UNEXPECTED, Verdict.MISSING, Verdict.NOT_SEEN, Verdict.PASS, Verdict.EXTERNAL,
                  Verdict.IGNORE, Verdict.UNDEFINED):
            if s in v_set:
                return s
        raise NotImplementedError(f"Merging of {verdicts}")


class Verdictable:
    """Base class for objects with verdict"""
    def get_verdict(self) -> Verdict:
        raise NotImplementedError()


# Verdict marker characters
Verdict_Markers: Dict[Verdict, str] = {
    Verdict.UNDEFINED: '*',
    Verdict.NOT_SEEN: '?',
    Verdict.UNEXPECTED: '+',
    Verdict.MISSING: '~',
    Verdict.FAIL: '!',
    Verdict.PASS: 'X',
    Verdict.EXTERNAL: '-',
    Verdict.IGNORE: '#',
}


class VerdictEvent:
    """Information about verdict assignment"""
    def __init__(self, event: Event, verdict=Verdict.UNDEFINED):
        self.verdict = verdict
        self.event = event

    def __repr__(self):
        return f"{self.verdict}: {self.event}"


class FlowEvent(VerdictEvent):
    """Flow event with verdict"""
    def __init__(self, endpoints: Tuple[AnyAddress, AnyAddress], reply: bool, event: Flow, verdict=Verdict.UNDEFINED):
        super().__init__(event, verdict)
        self.endpoints = endpoints
        self.reply = reply

    def __repr__(self):
        if self.reply:
            return f"{self.verdict}: {self.endpoints[1]} <- {self.endpoints[0]} {self.event.evidence}"
        return f"{self.verdict}: {self.endpoints[0]} -> {self.endpoints[1]} {self.event.evidence}"


class Status:
    """Entity or connection status"""
    def __init__(self, verdict=Verdict.UNDEFINED):
        self.verdict = verdict
        self.events: List[VerdictEvent] = []

    def is_expected(self) -> bool:
        """Is an expected connection?"""
        return self.verdict in {Verdict.NOT_SEEN, Verdict.PASS}

    def add_result(self, event: VerdictEvent):
        """Add new result"""
        self.verdict = Verdict.resolve(self.verdict, event.verdict)
        self.events.append(event)

    def reset(self, verdict: Verdict):
        """Reset model"""
        self.verdict = verdict
        self.events.clear()

    def __repr__(self):
        return f"{self.verdict.value}"
