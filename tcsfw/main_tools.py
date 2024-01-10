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

    def capture(self, label: str, name="") -> 'ToolLoader':
        tool = PCAPReader(self.builder.system, name)
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        sl.groups.append("pcap")
        return sl

    def nmap(self, label: str, xml_file: str) -> 'ToolLoader':
        tool = NMAPScan(self.builder.system)
        tool.base_files.append(pathlib.Path(xml_file))
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def censys(self, label: str, files: str) -> 'ToolLoader':
        tool = CensysScan(self.builder.system)
        tool.base_files.append(pathlib.Path(files))
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def tshark(self, label: str) -> 'ToolLoader':
        tool = TSharkReader(self.builder.system)
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def releases(self, label: str, software: [NodeInterface | SoftwareInterface], json_file: str):
        sw = software.get_software()
        tool = ReleaseReader(self.builder.system)
        tool.known_files[sw] = pathlib.Path(json_file)
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def testssl_sh(self, label: str, files: str) -> 'ToolLoader':
        tool = TestSSLScan(self.builder.system)
        tool.base_files.append(pathlib.Path(files))
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def spdx(self, label: str, software: [NodeInterface | SoftwareInterface], json_file: str, baseline=False):
        sw = software.get_software()
        tool = SPDXReader(self.builder.system)
        tool.known_files[sw] = pathlib.Path(json_file)
        sl = ToolLoader(tool, source_label=label)
        sl.baseline = baseline
        self.subs.append(sl)

    def vulnerabilities(self, label: str, software: [NodeInterface | SoftwareInterface], csv_file: str):
        sw = software.get_software()
        tool = VulnerabilityReader(self.builder.system)
        tool.known_files[sw] = pathlib.Path(csv_file)
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)

    def android_manifest(self, label: str, host: HostInterface, file: str, baseline=False):
        sw = Software.list_software(host.entity)
        assert host.entity.host_type == HostType.MOBILE and len(sw) == 1, "Expected mobile app with single SW"
        tool = AndroidManifestScan(self.builder.system)
        tool.known_files[sw[0]] = pathlib.Path(file)
        sl = ToolLoader(tool, source_label=label)
        sl.baseline = baseline
        self.subs.append(sl)
        return sl

    def browser_har(self, label: str, host: HostInterface, file: str, baseline=False):
        tool = HARScan(self.builder.system)
        tool.known_files[host.entity] = pathlib.Path(file)
        sl = ToolLoader(tool, source_label=label)
        sl.baseline = baseline
        self.subs.append(sl)
        return sl

    def zed_attack_proxy(self, label: str, file: str):
        tool = ZEDReader(self.builder.system)
        tool.base_files.append(pathlib.Path(file))
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def mitm_log(self, label: str, file: str) -> 'ToolLoader':
        tool = MITMLogReader(self.builder.system)
        tool.base_files = [pathlib.Path(file)]
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def ssh_audit(self, label: str, file: str) -> 'ToolLoader':
        """Use Ssh-audit tool"""
        tool = SSHAuditScan(self.builder.system)
        tool.base_files = [pathlib.Path(file)]
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

    def web_links(self, label: str) -> 'ToolLoader':
        """Check web links"""
        tool = WebChecker(self.builder.system)
        sl = ToolLoader(tool, source_label=label)
        self.subs.append(sl)
        return sl

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

    def other_tool(self, tool: CheckTool, as_first=False) -> 'ToolLoader':
        sl = ToolLoader(tool, source_label=tool.tool_label)
        if as_first:
            self.subs.insert(0, sl)
        else:
            self.subs.append(sl)
        return sl

    @classmethod
    def group(cls, group_label: str, *tools: 'ToolLoader'):
        """Create a group of tools"""
        for t in tools:
            t.groups.append(group_label)

    @classmethod
    def load_selected(cls, selection: Optional[str], all_loaders: Dict[str, List[SubLoader]]) -> List[SubLoader]:
        r = {}

        def add(loader: SubLoader):
            if loader not in r:
                r[loader] = None

        for sl in all_loaders.get("", []):
            add(sl)  # without labels, always included

        if selection is not None:
            # load only selected sources
            loaders = []
            for index, d in enumerate(selection.strip().split(",")):
                remove = d.startswith("^")
                if remove:
                    d = d[1:]
                if d in all_loaders:
                    d_loaders = all_loaders[d]
                    if remove:
                        # remove the loader or group
                        r_set = set(d_loaders)
                        if index == 0:  # start with ^, remove from all loaders
                            o_r = itertools.chain(*all_loaders.values())
                        else:
                            o_r = list(r.keys())
                        r.clear()
                        for lo in o_r:
                            if lo not in r_set:
                                add(lo)
                    else:
                        # add the loader or group
                        for lo in d_loaders:
                            add(lo)
                elif d:
                    raise Exception("Available tools are: " + ",".join(all_loaders.keys()))
        else:
            # load all sources
            for lo in itertools.chain(*all_loaders.values()):
                add(lo)

        return list(r.keys())

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

    def name(self, name: str) -> Self:
        """Provide human-friendly name for the source"""
        self.tool.tool.name = name
        return self

    def file(self, data_file: str) -> Self:
        """Add a data file"""
        self.tool.base_files.append(pathlib.Path(data_file))
        return self

    def pre_load(self, registry: Registry, labels: Dict[str, List['SubLoader']], coverage: RequirementClaimMapper):
        super().pre_load(registry, labels, coverage)
        for g in self.groups:
            labels.setdefault(g, []).append(self)

    def load(self, registry: Registry, coverage: RequirementClaimMapper):
        coverage.introduce_tool_plans(self.tool_plan_coverage)
        self.tool.coverage(coverage.tool_coverage)
        self.tool.load_baseline = self.baseline
        self.tool.run_tool(registry, self.get_source())

    # NOTE: This list is bound to be incomplete :(
    TOOLS = {
        'censys': lambda bf: CensysScan(bf),
        'har': lambda bf: HARScan(bf),
        'mitm-log': lambda bf: MITMLogReader(bf),
        'pcap': lambda bf: PCAPReader(bf),
        'spdx': lambda bf: SPDXReader(bf),
        'ssh-audit': lambda bf: SSHAuditScan(bf),
        'tshark': lambda bf: TSharkReader(bf),
    }

    @classmethod
    def load_by_command(cls, registry: Registry, coverage: RequirementClaimMapper, command: str):
        cmd, _, arg = command.partition(":")
        con = cls.TOOLS.get(cmd.strip())
        if con is None:
            raise ValueError(f"Unknown tool '{cmd}', use one of: " + ", ".join(sorted(cls.TOOLS.keys())))
        if not arg.strip():
            arg = "."
        tool: CheckTool = con(registry.get_system())
        tl = ToolLoader(tool, tool.tool_label)
        tool.run_tool(registry, tl.get_source(), arguments=arg)
        tool.coverage(coverage.tool_coverage)


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
