"""Mitmproxy log reader"""

from io import BytesIO, TextIOWrapper
import re

from tcsfw.address import HWAddresses
from tcsfw.event_interface import EventInterface
from tcsfw.model import IoTSystem
from tcsfw.property import Properties
from tcsfw.services import NameEvent
from tcsfw.tools import BaseFileCheckTool
from tcsfw.traffic import EvidenceSource, Evidence, IPFlow
from tcsfw.verdict import Verdict


class MITMLogReader(BaseFileCheckTool):
    """Read MITM log created the tls_check MITMproxy add-on"""
    def __init__(self, system: IoTSystem):
        super().__init__("mitm", system)
        self.tool.name = "MITM tool"
        self.data_file_suffix = ".log"

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        """Read a log file"""
        evidence = Evidence(source)
        names = set()

        # Format:
        # [timestamp] <event>,<source ip>,<source port>,<target ip>,<target port>,<sni>,<message>

        matcher = re.compile(r"\[[^]]+] ([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),.*")

        dupes = set()
        fresh_c, dupe_c = 0, 0

        with TextIOWrapper(data) as f:
            while True:
                raw_line = f.readline()
                if not raw_line:
                    break
                raw_line = raw_line.strip()
                m = matcher.match(raw_line)
                if m is None:
                    self.logger.warning("Skip bad MITM log line: %s", raw_line)
                    continue
                ev, s_add, s_port, d_add, d_port, d = m.groups()
                if ev not in {"tls_established", "tls_failed"}:
                    continue

                # avoid repeating same event
                dupe_key = ev, s_add, d_add, d_port  # source port can change
                if dupe_key in dupes:
                    dupe_c += 1
                    continue
                dupes.add(dupe_key)
                fresh_c += 1

                flow = IPFlow.tcp_flow(
                    # we do not know HW addresses from the log
                    HWAddresses.NULL.data, s_add, int(s_port),
                    HWAddresses.NULL.data, d_add, int(d_port))
                flow.evidence = evidence
                if d:
                    # learn SNI, no peers in event, the connection will be UNEXPECTED if it is not expected
                    name = NameEvent(evidence, None, d, flow.target[1])
                    if name not in names:
                        interface.name(name)
                        names.add(name)
                # Put verdict to connection message
                v = Verdict.PASS if ev == "tls_failed" else Verdict.FAIL
                Properties.MITM.put_verdict(flow.properties, v)
                interface.connection(flow)

        return True
