"""ZED attack proxy result reader"""

from io import BufferedReader
import json
from datetime import datetime
from typing import List, Set, Any

from toolsaf.common.address import EndpointAddress, Protocol, DNSName
from toolsaf.core.event_interface import EventInterface, PropertyAddressEvent
from toolsaf.core.model import IoTSystem
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.adapters.tools import SystemWideTool
from toolsaf.common.traffic import EvidenceSource, Evidence
from toolsaf.common.verdict import Verdict


class ZEDReader(SystemWideTool):
    """Read ZED attack proxy scanning results for a software"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("zap", system)
        self.tool.name = "ZED Attack Proxy"
        self.data_file_suffix = ".json"

    def process_file(self, data: BufferedReader, file_name: str,
                     interface: EventInterface, source: EvidenceSource) -> bool:
        raw_file = json.load(data)

        evidence = Evidence(source)

        source.timestamp = datetime.strptime(raw_file["@generated"], "%a, %d %b %Y %H:%M:%S")

        for raw in raw_file["site"]:
            host = raw["@host"]
            port = int(raw["@port"])
            ep = EndpointAddress(DNSName.name_or_ip(host), Protocol.TCP, port)
            ps = self._read_alerts(interface, evidence, ep, raw.get("alerts", []))
            exp = f"{self.tool.name} scan completed"
            # Web best practice
            web_key = Properties.WEB_BEST
            ev = PropertyAddressEvent(evidence, ep, web_key.value_set(ps, explanation=exp))
            interface.property_address_update(ev)
            # also HTTP best practice
            http_key = Properties.PROTOCOL.append_key(Protocol.HTTP.value).append_key("best-practices")
            ev = PropertyAddressEvent(evidence, ep, http_key.value_set({web_key}))
            interface.property_address_update(ev)

        return True

    def _read_alerts(self, interface: EventInterface, evidence: Evidence, endpoint: EndpointAddress, raw: List[Any]) \
            -> Set[PropertyKey]:
        ps = set()
        for raw_a in raw:
            name = raw_a["name"]
            riskcode = int(raw_a["riskcode"])
            if riskcode < 2:
                self.logger.debug("Skipping riskcode < 2: %s", name)
                continue
            ref = raw_a["alertRef"]
            key = PropertyKey(self.tool_label, ref)
            exp = f"{self.tool.name} ({ref}): {name}"
            ev = PropertyAddressEvent(evidence, endpoint, key.verdict(Verdict.FAIL, exp))
            interface.property_address_update(ev)
            ps.add(key)
        return ps
