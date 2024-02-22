from io import BytesIO, TextIOWrapper
import pathlib
import re
from typing import List

from tcsfw.address import HWAddresses, Protocol
from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem, Connection, Service
from tcsfw.property import Properties, PropertyKey
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
                c = interface.connection(flow)
                if not c.is_expected():
                    continue  # Non-expected connection, who cares...
                v = Verdict.PASS if ev == "tls_failed" else Verdict.FAIL
                ev = PropertyEvent(evidence, c, Properties.MITM.verdict(v))
                interface.property_update(ev)

        return True
