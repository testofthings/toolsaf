import pathlib
import re
from typing import List

from tcsfw.address import HWAddresses, Protocol
from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem, Connection, Service
from tcsfw.property import Properties, PropertyVerdict, PropertyKey
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

    def _check_file(self, data_file: pathlib.Path, interface: EventInterface, source: EvidenceSource):
        """Read a log file"""
        evidence = Evidence(source, tail_ref=data_file.as_posix())
        names = set()

        # Format:
        # [timestamp] <event>,<source ip>,<source port>,<target ip>,<target port>,<sni>,<message>

        matcher = re.compile(r"\[[^]]+] ([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),.*")

        with data_file.open() as f:
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
                    HWAddresses.NULL.data, s_add, int(s_port),
                    HWAddresses.NULL.data, d_add, int(d_port))
                flow.evidence = evidence
                if d:
                    # learn SNI
                    name = NameEvent(evidence, None, d, flow.target[1])
                    if name not in names:
                        interface.name(name)
                        names.add(name)
                c = interface.connection(flow)
                if not c.status.is_expected():
                    continue  # Non-expected connection, who cares...
                v = Verdict.PASS if ev == "tls_failed" else Verdict.FAIL
                ev = PropertyEvent(evidence, c, Properties.MITM.value(v))
                interface.property_update(ev)

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        if isinstance(entity, Connection):
            t = entity.target
            if isinstance(t, Service) and t.protocol == Protocol.TLS:
                return [Properties.MITM]  # TLS can MITM
        return []
