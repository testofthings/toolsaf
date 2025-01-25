"""Tool factory"""

from typing import Dict, List, Optional, Type, Union
from toolsaf.adapters.android_manifest_scan import AndroidManifestScan
from toolsaf.adapters.censys_scan import CensysScan
from toolsaf.adapters.har_scan import HARScan
from toolsaf.adapters.certmitm_reader import CertMITMReader
from toolsaf.adapters.nmap_scan import NMAPScan
from toolsaf.adapters.pcap_reader import PCAPReader
from toolsaf.adapters.ping_command import PingCommand
from toolsaf.adapters.github_releases import GithubReleaseReader
from toolsaf.adapters.setup_reader import SetupCSVReader
from toolsaf.adapters.shell_commands import ShellCommandPs, ShellCommandSs
from toolsaf.adapters.shodan_scan import ShodanScan
from toolsaf.adapters.spdx_reader import SPDXReader
from toolsaf.adapters.ssh_audit_scan import SSHAuditScan
from toolsaf.adapters.testsslsh_scan import TestSSLScan
from toolsaf.adapters.tools import ToolAdapter, SimpleFlowTool
from toolsaf.adapters.tshark_reader import TSharkReader
from toolsaf.adapters.vulnerability_reader import VulnerabilityReader
from toolsaf.adapters.web_checker import WebChecker
from toolsaf.adapters.zed_reader import ZEDReader
from toolsaf.core.model import IoTSystem
from toolsaf.core.ignore_rules import IgnoreRules


class ToolDepiction:
    """Tool depiction"""
    def __init__(self, file_type: Union[str|List[str]],
                 tool_class: Union[Type[ToolAdapter], Dict[str, Type[ToolAdapter]]],
                 extension: str=""):
        file_types = file_type if isinstance(file_type, list) else [file_type]
        self.file_type = file_types[0]  # primary
        self.tools: Dict[str, Type[ToolAdapter]] = {}
        if isinstance(tool_class, dict):
            assert not extension
            self.tools = tool_class
        else:
            assert isinstance(tool_class, type)
            self.tools[extension] = tool_class
        for ft in file_types:
            assert ft not in self.ToolsByType, f"Two tools for file type '{ft}'"
            self.ToolsByType[ft] = self

    def filter_files_itself(self) -> bool:
        """Does the tool filter files itself?"""
        return len(self.tools) == 1 and "" in self.tools

    def create_tool(self, system: IoTSystem, file_extension: str="",
                    ignore_rules: Optional[IgnoreRules]=None) -> Optional[ToolAdapter]:
        """Create tool, optionally by data file extension"""
        if file_extension:
            file_extension = file_extension.lower()
            file_extension = file_extension[1:] if file_extension.startswith(".") else file_extension
            tc = self.tools.get(file_extension)
        else:
            tc = next(iter(self.tools.values()), None)
        if tc is None:
            return None
        # NOTE: All constructors are assumed to only consume system, and provide name for ToolAdapter
        tool = tc(system)  # type: ignore [call-arg, arg-type]
        assert tool.system == system  # ...try to assert that this happens
        tool.ignore_rules = ignore_rules
        return tool

    def __repr__(self) -> str:
        return self.file_type

    ToolsByType: Dict[str, 'ToolDepiction'] = {}


class ToolFinderImplementation:
    """Tool finder implementation"""
    def __init__(self) -> None:
        assert not ToolDepiction.ToolsByType, "Only one instance of ToolFinder should be created"

        # NOTE: Tools without given file extension and given all files from directory.
        #       They are expected to only use those which make sense for them.

        self.apk = ToolDepiction("apk", AndroidManifestScan, extension="xml")
        self.censys = ToolDepiction("censys", CensysScan)
        self.har = ToolDepiction("har", HARScan, extension="json")
        self.http = ToolDepiction("http", WebChecker, extension="http")
        self.certmitm = ToolDepiction("certmitm", CertMITMReader, extension="zip")
        self.nmap = ToolDepiction("nmap", NMAPScan, extension="xml")
        self.github_releases = ToolDepiction("github-releases", GithubReleaseReader)
        self.ping = ToolDepiction("ping", PingCommand, extension="log")
        self.pcap = ToolDepiction(["capture", ""], PCAPReader, extension="pcap")  # Default tool - file_type ""
        self.pcap = ToolDepiction("capture-json", TSharkReader, extension="json")
        self.pcap_flow = ToolDepiction("exp-flow", SimpleFlowTool, extension="json")
        self.setup = ToolDepiction("setup", SetupCSVReader, extension="csv")
        self.shell_ps = ToolDepiction("shell-ps", ShellCommandPs)
        self.shell_ss = ToolDepiction("shell-ss", ShellCommandSs)
        self.shodan = ToolDepiction("shodan", ShodanScan, extension="json")
        self.sdpx = ToolDepiction("spdx", SPDXReader)
        self.ssh_audit = ToolDepiction("ssh-audit", SSHAuditScan)
        self.testssl = ToolDepiction("testssl", TestSSLScan)
        self.vulnerabilities = ToolDepiction("blackduck-vulnerabilities", VulnerabilityReader)
        self.zap = ToolDepiction("zap", ZEDReader, extension="json")

    def by_file_type(self, file_type: str) -> ToolDepiction:
        """Get tool by name"""
        cl = ToolDepiction.ToolsByType.get(file_type)
        if cl is None:
            raise ValueError(f"Unknown file_type '{file_type}'")
        return cl


# The tool finder singleton
ToolFinder = ToolFinderImplementation()
