import itertools
import pathlib
from typing import Any, List, Dict, Tuple, Self, Optional

from tcsfw.android_manifest_scan import AndroidManifestScan
from tcsfw.batch_import import LabelFilter
from tcsfw.censys_scan import CensysScan
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.components import Software
from tcsfw.event_interface import PropertyEvent
from tcsfw.har_scan import HARScan
from tcsfw.requirement import SelectorContext
from tcsfw.selector import Locations, RequirementSelector
from tcsfw.main_basic import SubLoader, SystemInterface, NodeInterface, SoftwareInterface, HostInterface
from tcsfw.mitm_log_reader import MITMLogReader
from tcsfw.model import EvidenceNetworkSource, HostType
from tcsfw.nmap_scan import NMAPScan
from tcsfw.pcap_reader import PCAPReader
from tcsfw.property import PropertyKey
from tcsfw.registry import Registry
from tcsfw.releases import ReleaseReader
from tcsfw.spdx_reader import SPDXReader
from tcsfw.ssh_audit_scan import SSHAuditScan
from tcsfw.testsslsh_scan import TestSSLScan
from tcsfw.tools import CheckTool
from tcsfw.traffic import Evidence, EvidenceSource, Flow, Tool
from tcsfw.tshark_reader import TSharkReader
from tcsfw.verdict import Verdict
from tcsfw.vulnerability_reader import VulnerabilityReader
from tcsfw.web_checker import WebChecker
from tcsfw.zed_reader import ZEDReader


class EvidenceLoader(SubLoader):
    """Load evidence files"""
    def __init__(self, builder: SystemInterface):
        super().__init__("Loader")
        self.builder = builder
        self.subs: List[SubLoader] = []

    def fabricate(self, label: str) -> 'FabricationLoader':
        """Fabricate evidence for testing or visualization"""
        sl = FabricationLoader(label)
        self.subs.append(sl)
        return sl

    @classmethod
    def group(cls, group_label: str, *tools: 'ToolPlanLoader'):
        """Create a group of tools"""
        for t in tools:
            # t.load_label = group_label  # label in source filtering
            t.groups.append(group_label)


class FabricationLoader(SubLoader):
    """Fabricate evidence for testing or visualization"""
    def __init__(self, source_label: str):
        super().__init__(source_label)
        self.flows: List[Flow] = []

    def connection(self, flow: Flow) -> Self:
        """Add a connection"""
        self.flows.append(flow)
        return self

    def load(self, registry: Registry, coverage: RequirementClaimMapper, filter: LabelFilter):
        if not filter.filter(self.source_label):
            return
        evi = Evidence(self.get_source())
        for f in self.flows:
            f.evidence = evi  # override evidence
            registry.connection(f)


class ToolPlanLoader(SubLoader):
    def __init__(self, group: Tuple[str, str]):
        super().__init__(group[1])    # group[0] is e.g. 'basic-tools', 'advanced-tools', 'custom-tools'
        self.source_label = group[1]  # group[1] is fancy names for them (just captialize?)
        self.location = Locations.SYSTEM
        self.properties: Dict[PropertyKey, Any] = {}
        self.groups = ["planning", group[0]]

    def load(self, registry: Registry, coverage: RequirementClaimMapper, filter: LabelFilter):
        for g in self.groups:
            if g in filter.excluded:
                return  # explicitly excluded
            if g in filter.included:
                break  # explicitly included
        else:
           return  # plans must be explicitly included

        evidence = Evidence(self.get_source())
        for p, v in self.properties.items():
            entities = self.location.select(registry.get_system(), SelectorContext())
            for ent in entities:
                ev = PropertyEvent(evidence, ent, (p, v))
                registry.property_update(ev)
