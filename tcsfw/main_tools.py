import itertools
import pathlib
from typing import List, Dict, Tuple, Self, Optional

from tcsfw.android_manifest_scan import AndroidManifestScan
from tcsfw.censys_scan import CensysScan
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.components import Software
from tcsfw.har_scan import HARScan
from tcsfw.selector import RequirementSelector
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

    def plan_tool(self, label: str, tool_name: str, location: RequirementSelector, *key: Tuple[str, ...]) -> 'ToolLoader':
        """Plan use of a tool using the property keys it is supposed to set"""
        tool = CheckTool(tool_name, self.builder.system)  # null tool
        sl = ToolLoader(tool, source_label=label)
        sl.groups.append("planned")
        tl = sl.tool_plan_coverage.setdefault(location, [])
        for k in key:
            tl.append((Tool(tool_name), PropertyKey.create(k)))
        self.subs.append(sl)
        return sl

    @classmethod
    def group(cls, group_label: str, *tools: 'ToolLoader'):
        """Create a group of tools"""
        for t in tools:
            t.groups.append(group_label)

    def pre_load(self, registry: Registry, labels: Dict[str, List['SubLoader']], coverage: RequirementClaimMapper):
        super().pre_load(registry, labels, coverage)
        labels.update(self.groups)


class ToolLoader(SubLoader):
    def __init__(self, tool: CheckTool, source_label: str = None):
        super().__init__(tool.tool.name)
        self.tool = tool
        if source_label is not None:
            self.source_label = source_label
        self.tool_plan_coverage: Dict[RequirementSelector, List[Tuple[Tool, PropertyKey]]] = {}
        self.groups: List[str] = []

    def pre_load(self, registry: Registry, labels: Dict[str, List['SubLoader']], coverage: RequirementClaimMapper):
        super().pre_load(registry, labels, coverage)
        for g in self.groups:
            labels.setdefault(g, []).append(self)

class FabricationLoader(SubLoader):
    """Fabricate evidence for testing or visualization"""
    def __init__(self, source_label: str):
        super().__init__(source_label)
        self.flows: List[Flow] = []

    def connection(self, flow: Flow) -> Self:
        """Add a connection"""
        self.flows.append(flow)
        return self

    def load(self, registry: Registry, coverage: RequirementClaimMapper):
        evi = Evidence(self.get_source())
        for f in self.flows:
            f.evidence = evi  # override evidence
            registry.connection(f)
