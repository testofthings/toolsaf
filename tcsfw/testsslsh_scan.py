from io import BytesIO
import json
import pathlib
from typing import Dict, List, Optional

from tcsfw.address import AnyAddress, Protocol
from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyAddressEvent
from tcsfw.model import Service, IoTSystem, NetworkNode
from tcsfw.property import PropertyKey, Properties, PropertyKey
from tcsfw.registry import Registry
from tcsfw.tools import EndpointCheckTool
from tcsfw.traffic import Evidence, EvidenceSource
from tcsfw.basics import Verdict


class TestSSLScan(EndpointCheckTool):
    def __init__(self, system: IoTSystem):
        super().__init__("testssl", ".json", system)
        self.tool.name = "Testssl.sh"
        self.property_key = Properties.PROTOCOL.append_key("tls")

    def _filter_node(self, node: NetworkNode) -> bool:
        return isinstance(node, Service)

    def process_stream(self,  endpoint: AnyAddress, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource):
        raw = json.load(data_file)
        evi = Evidence(source)
        self.do_scan(interface, endpoint, raw, evi)

    def do_scan(self, event_sink: EventInterface, endpoint: AnyAddress, raw: Dict, evidence: Evidence):
        """Scan TLS service"""
        bp_keys = set()  # best practices
        vn_keys = set()  # vulnerabilities
        for f in raw:
            f_id = f['id']
            if f_id == 'overall_grade':
                continue
            rm, _, ip = f['ip'].partition("/")
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
