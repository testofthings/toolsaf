from datetime import datetime
from typing import Tuple, List

import requests

from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem
from tcsfw.property import Properties, PropertyKey
from tcsfw.tools import NodeCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.verdict import Verdict


class WebChecker(NodeCheckTool):
    """Check web pages"""
    def __init__(self, system: IoTSystem):
        super().__init__("web", system)
        self.tool.name = "Web check"

    def run_tool(self, interface: EventInterface, source: EvidenceSource, arguments: str = None):
        source = source.rename(self.tool.name)
        for key, url in self.system.online_resources.items():
            self.logger.info("Checking on-line resource %s", url)
            ok, exp = self._check_url(url)
            kv = Properties.DOCUMENT_AVAILABILITY.append_key(key).value(Verdict.PASS if ok else Verdict.FAIL, exp)
            source.timestamp = datetime.now()
            evidence = Evidence(source, url)
            ev = PropertyEvent(evidence, self.system, kv)
            interface.property_update(ev)

    def _check_url(self, url: str) -> Tuple[bool, str]:
        res = requests.get(url, headers={
            "User-Agent": "TCSFW web checker",
        })
        return res.status_code == 200, f"{url} {res.status_code} {res.reason}"

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        if isinstance(entity, IoTSystem) and entity.online_resources:
            return [Properties.DOCUMENT_AVAILABILITY]
        return []

