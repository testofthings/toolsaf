"""Ssh-audit output reading tool"""

from io import BufferedReader
import json
from typing import Dict, Set

from toolsaf.common.address import AnyAddress, Protocol
from toolsaf.core.event_interface import PropertyAddressEvent, EventInterface
from toolsaf.core.model import Service, IoTSystem, NetworkNode
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.adapters.tools import EndpointTool
from toolsaf.common.traffic import Evidence, EvidenceSource
from toolsaf.common.verdict import Verdict


class SSHAuditScan(EndpointTool):
    """Ssh-audit output reading tool"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("ssh-audit", ".json", system)
        self.tool.name = "SSH audit"
        self.property_key = Properties.PROTOCOL.append_key("ssh")

    def filter_node(self, node: NetworkNode) -> bool:
        if not isinstance(node, Service):
            return False
        return node.protocol == Protocol.SSH

    def process_endpoint(self, endpoint: AnyAddress, stream: BufferedReader, interface: EventInterface,
                       source: EvidenceSource) -> None:
        """Scan network node"""
        raw = json.load(stream)

        evidence = Evidence(source)

        for cve in raw.get("cves", []):
            key = PropertyKey(self.tool_label, cve["name"].lower())
            explanation = f"CVSSv2: {cve['cvssv2']}, {cve['description']}"
            interface.property_address_update(
                PropertyAddressEvent(evidence, endpoint, key.verdict(Verdict.FAIL, explanation=explanation))
            )

        issues: Dict[PropertyKey, str] = {}

        def make_issue(op: str, kind: str, item: Dict[str, str]) -> None:
            op_s = "Change" if op == "chg" else "Delete"
            key = PropertyKey(self.tool_label, op, kind, item['name'])
            issues[key] = f"{op_s} {kind} {item['name']}"

        rec = raw.get("recommendations", {}).get("critical", {})
        for op, kinds in rec.items():
            for kind, items in kinds.items():
                for i in items:
                    make_issue(op, kind, i)

        bp_keys: Set[PropertyKey] = set()  # best practices
        vn_keys: Set[PropertyKey] = set()  # vulnerabilities (none)
        for key, exp in issues.items():
            self.logger.info("SSH issue %s: %s", key, exp)
            ev = PropertyAddressEvent(evidence, endpoint, key.verdict(Verdict.FAIL, f"{self.tool.name}: {exp}"))
            bp_keys.add(key)
            interface.property_address_update(ev)

        # send several property events
        key = self.property_key
        events = [
            key.verdict(Verdict.PASS, f"{self.tool.name} confirm SSH"),
            key.append_key("best-practices").value_set(bp_keys, f"{self.tool.name} best practices"),
            key.append_key("no-vulnz").value_set(vn_keys, f"{self.tool.name} no vulnerabilities"),
            Properties.ENCRYPTION.verdict(Verdict.PASS, f"{self.tool.name} encryption"),
            Properties.AUTHENTICATION.verdict(Verdict.PASS, f"{self.tool.name} authentication")
        ]
        for p in events:
            ev = PropertyAddressEvent(evidence, endpoint, p)
            interface.property_address_update(ev)
