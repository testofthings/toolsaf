"""Testssl.sh output reading tool"""

from io import BufferedReader
import json
from typing import Dict, Any, List

from toolsaf.common.address import AnyAddress
from toolsaf.core.event_interface import EventInterface, PropertyAddressEvent
from toolsaf.core.model import Service, IoTSystem, NetworkNode
from toolsaf.common.property import PropertyKey, Properties
from toolsaf.adapters.tools import EndpointTool
from toolsaf.common.traffic import Evidence, EvidenceSource
from toolsaf.common.verdict import Verdict


class TestSSLScan(EndpointTool):
    """Testssl.sh output reading tool"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("testssl", ".json", system)
        self.tool.name = "Testssl.sh"
        self.property_key = Properties.PROTOCOL.append_key("tls")

    def filter_node(self, node: NetworkNode) -> bool:
        return isinstance(node, Service)

    def process_endpoint(self,  endpoint: AnyAddress, stream: BufferedReader, interface: EventInterface,
                       source: EvidenceSource) -> None:
        raw = json.load(stream)
        evi = Evidence(source)
        self.do_scan(interface, endpoint, raw, evi)

    def do_scan(self, event_sink: EventInterface, endpoint: AnyAddress, raw: List[Dict[str, Any]],
                evidence: Evidence) -> None:
        """Scan TLS service"""
        bp_keys = set()  # best practices
        vn_keys = set()  # vulnerabilities
        for f in raw:
            f_id = f['id']
            if f_id == 'overall_grade':
                continue
            severity = f['severity']
            finding = f['finding']
            if severity in {'INFO', 'OK', 'LOW'} or finding == '--':
                # self.logger.debug("Ignoring %s: %s", f_id, finding)
                continue
            self.logger.info("Issue %s: %s", f_id, finding)

            exp = f"{self.tool.name} ({f_id}): {finding}"
            kv = PropertyKey(self.tool_label, f_id).verdict(Verdict.FAIL, exp)
            ev = PropertyAddressEvent(evidence, endpoint, kv)
            if severity in {'MEDIUM'}:
                vn_keys.add(kv[0])
            else:
                bp_keys.add(kv[0])
            event_sink.property_address_update(ev)

        # send several property events
        key = self.property_key
        events = [
            key.verdict(Verdict.PASS, f"{self.tool.name} confirm TLS"),
            key.append_key("best-practices").value_set(bp_keys, f"{self.tool.name} best practices"),
            key.append_key("no-vulnz").value_set(vn_keys, f"{self.tool.name} no vulnerabilities"),
            Properties.ENCRYPTION.verdict(Verdict.PASS, f"{self.tool.name} encryption")
        ]
        for p in events:
            ev = PropertyAddressEvent(evidence, endpoint, p)
            event_sink.property_address_update(ev)
