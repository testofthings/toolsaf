"""Check host availability by ping"""


from io import BytesIO, TextIOWrapper
import re
from typing import Optional, Tuple
from tcsfw.address import IPAddress
from tcsfw.event_interface import EventInterface, PropertyAddressEvent
from tcsfw.model import IoTSystem
from tcsfw.property import Properties
from tcsfw.tools import SystemWideTool
from tcsfw.traffic import Evidence, EvidenceSource
from tcsfw.verdict import Verdict


class PingCommand(SystemWideTool):
    """Ping command"""
    def __init__(self, system: IoTSystem):
        super().__init__("ping", system)
        self.data_file_suffix = ".ping"
        self.tool.name = "Ping"

    def process_file(self, data: BytesIO, _file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        ev = Evidence(source)
        with TextIOWrapper(data) as f:
            while True:
                line = f.readline()
                if not line:
                    break
                r = self.parse_ping_line(line)
                if r:
                    ok, addr = r
                    p = Properties.EXPECTED.verdict(Verdict.PASS if ok else Verdict.FAIL, line)
                    ev = PropertyAddressEvent(ev, IPAddress.new(addr), p)
                    interface.property_address_update(ev)
                    break
        return True

    IPv4_regexp = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    IPv6_regexp = re.compile(r'([a-fA-F0-9:]{8,39})')

    @classmethod
    def parse_ping_line(cls, line: str) -> Optional[Tuple[bool, str]]:
        """Return true if verdict resolved: Success-flag and IP address"""
        line = line.lower()
        ok = "bytes from" in line
        fail = "nreachable" in line
        addr = ""
        m = cls.IPv4_regexp.search(line)
        if m:
            addr = m.group(1)
        else:
            m = cls.IPv6_regexp.search(line)
            if m:
                addr = m.group(1)
        if addr and (ok or fail):
            return ok, addr
        return None
