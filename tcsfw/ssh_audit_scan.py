from io import BytesIO
import json
import pathlib
from typing import Dict, List

from tcsfw.address import AnyAddress, Protocol
from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyAddressEvent, EventInterface
from tcsfw.model import Service, IoTSystem, NetworkNode
from tcsfw.property import Properties, PropertyKey
from tcsfw.tools import EndpointCheckTool
from tcsfw.traffic import Evidence, EvidenceSource
from tcsfw.verdict import Verdict


class SSHAuditScan(EndpointCheckTool):
    def __init__(self, system: IoTSystem):
        super().__init__("ssh-audit", ".json", system)
        self.tool.name = "SSH audit"
        self.property_key = Properties.PROTOCOL.append_key("ssh")

    def _filter_node(self, node: NetworkNode) -> bool:
        if not isinstance(node, Service):
            return False
        return node.protocol == Protocol.SSH

    def process_stream(self, endpoint: AnyAddress, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource):
        """Scan network node"""
        raw = json.load(data_file)

        evidence = Evidence(source)

        # NOTE: There would be CVEs to collect, if someone listens for them!
        issues = {}

        def make_issue(op: str, kind: str, item: Dict):
            op_s = "Change" if op == "chg" else "Delete"
            key = PropertyKey(self.tool_label, op, kind, item['name'])
            issues[key] = f"{op_s} {kind} {item['name']}"

        rec = raw.get("recommendations", {}).get("critical", {})
        for op, kinds in rec.items():
            for kind, items in kinds.items():
                for i in items:
                    make_issue(op, kind, i)

        p_keys = set()
        for key, exp in issues.items():
            self.logger.info("SSH issue %s: %s", key, exp)
            ev = PropertyAddressEvent(evidence, endpoint, key.verdict(Verdict.FAIL, f"{self.tool.name}: {exp}"))
            p_keys.add(key)
            interface.property_address_update(ev)

        # scan summary at the end
        exp = f"{self.tool.name} scan completed"
        kv = self.property_key.value_set(p_keys, explanation=exp)
        ev = PropertyAddressEvent(evidence, endpoint, kv)
        interface.property_address_update(ev)

        # SSH is encryption
        ev = PropertyAddressEvent(evidence, endpoint,
                                  Properties.ENCRYPTION.value_set({kv[0]}, explanation="SSH for encryption"))
        interface.property_address_update(ev)

        # SSH is assumed to be good for authentication
        ev = PropertyAddressEvent(evidence, endpoint,
                                  Properties.AUTHENTICATION.value_set({kv[0]}, explanation="SSH for authentication"))
        interface.property_address_update(ev)

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        if isinstance(entity, Service) and entity.protocol in {Protocol.SSH}:
            ks = []
            key = self.property_key
            ks.extend([key, key.append_key("best-practices"), key.append_key("no-vulnz"), Properties.ENCRYPTION])
            # also authentication
            key = Properties.AUTHENTICATION
            ks.extend([key, key.append_key("best-practices"), key.append_key("no-vulnz")])
            return ks
        return []

