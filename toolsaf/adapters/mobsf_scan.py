"""Tool to read MobSF static scan results"""

import json
from io import BufferedReader
from typing import List, Dict, Any, Optional

from toolsaf.adapters.tools import EndpointTool
from toolsaf.common.verdict import Verdict
from toolsaf.common.address import AnyAddress
from toolsaf.common.property import PropertyKey
from toolsaf.common.traffic import EvidenceSource, Evidence
from toolsaf.core.model import IoTSystem
from toolsaf.core.components import Software
from toolsaf.core.event_interface import PropertyEvent, EventInterface


class MobSFScan(EndpointTool):
    """MobSF json tool"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("mobsf", ".json", system)
        self.tool.name = "MobSF Scan"

    def _get_certificate_finding_events(self, software: Software, evidence: Evidence,
                                        scan_results: Dict[str, Any]) -> List[PropertyEvent]:
        """Extract PropertyEvents from certificate analysis results"""
        property_events = []
        for entry in scan_results.get("certificate_analysis", {}).get("certificate_findings", []):
            severity, description, title = entry[0], entry[1], entry[2]
            if severity != "info":
                key = PropertyKey(self.tool_label, "cert", "-".join(title.split(" ")))
                property_events.append(
                    PropertyEvent(evidence, software, key.verdict(Verdict.FAIL, explanation=description))
                )
        return property_events

    def _get_possible_hardcoded_secrets_event(self, software: Software, evidence: Evidence,
                                              scan_results: Dict[str, Any]) -> Optional[PropertyEvent]:
        """Extract number of possible hardcoded secrets from analysis results"""
        num_possible_secrets = len(scan_results.get("secrets", []))
        if num_possible_secrets > 0:
            return PropertyEvent(
                evidence,
                software,
                PropertyKey(self.tool_label, "secrets") \
                    .verdict(Verdict.FAIL, f"Found {num_possible_secrets} possible hardocded secrets")
            )
        return None



    def process_endpoint(self, endpoint: AnyAddress, stream: BufferedReader, interface: EventInterface,
                         source: EvidenceSource) -> None:
        node = self.system.get_endpoint(endpoint)
        software = Software.get_software(node)
        assert software
        scan_results: Dict[str, Any] = json.load(stream)
        evidence = Evidence(source)

        # Could get app permissions here in the future

        for entry in self._get_certificate_finding_events(software, evidence, scan_results):
            interface.property_update(entry)

        ev = self._get_possible_hardcoded_secrets_event(software, evidence, scan_results)
        if ev:
            interface.property_update(ev)
