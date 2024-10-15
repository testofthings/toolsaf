"""Tool factory"""

from typing import Dict, List, Optional, Type, Union
from tcsfw.android_manifest_scan import AndroidManifestScan
from tcsfw.censys_scan import CensysScan
from tcsfw.har_scan import HARScan
from tcsfw.mitm_log_reader import MITMLogReader
from tcsfw.model import IoTSystem
from tcsfw.nmap_scan import NMAPScan
from tcsfw.pcap_reader import PCAPReader
from tcsfw.ping_command import PingCommand
from tcsfw.releases import ReleaseReader
from tcsfw.setup_reader import SetupCSVReader
from tcsfw.shell_commands import ShellCommandPs, ShellCommandSs
from tcsfw.spdx_reader import SPDXReader
from tcsfw.ssh_audit_scan import SSHAuditScan
from tcsfw.testsslsh_scan import TestSSLScan
from tcsfw.tools import ToolAdapter, SimpleFlowTool
from tcsfw.tshark_reader import TSharkReader
from tcsfw.vulnerability_reader import VulnerabilityReader
from tcsfw.web_checker import WebChecker
from tcsfw.zed_reader import ZEDReader


class ToolDepiction:
    """Tool depiction"""
    def __init__(self, file_type: Union[str|List[str]],
                 tool_class: Union[Type[ToolAdapter], Dict[str, Type[ToolAdapter]]],
                 extension=""):
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

    def create_tool(self, system: IoTSystem, file_extension="") -> Optional[ToolAdapter]:
        """Create tool, optionally by data file extension"""
        if file_extension:
            file_extension = file_extension.lower()
            file_extension = file_extension[1:] if file_extension.startswith(".") else file_extension
            tc = self.tools.get(file_extension)
        else:
            tc = next(iter(self.tools.values()), None)
        if tc is None:
            return None
        return tc(system)

    def __repr__(self) -> str:
        return self.file_type

    ToolsByType: Dict[str, 'ToolDepiction'] = {}


class ToolFinderImplementation:
    """Tool finder implementation"""
    def __init__(self):
        assert not ToolDepiction.ToolsByType, "Only one instance of ToolFinder should be created"

        # NOTE: Tools without given file extension and given all files from directory.
        #       They are expected to only use those which make sense for them.

        self.apk = ToolDepiction("apk", AndroidManifestScan, extension="xml")
        self.censys = ToolDepiction("censys", CensysScan)
        self.har = ToolDepiction("har", HARScan, extension="json")
        self.http = ToolDepiction("http", WebChecker, extension="http")
        self.mitm_proxy = ToolDepiction("mitmproxy", MITMLogReader, extension="log")
        self.nmap = ToolDepiction("nmap", NMAPScan, extension="xml")
        self.releases = ToolDepiction("github-releases", ReleaseReader)
        self.ping = ToolDepiction("ping", PingCommand, extension="log")
        self.pcap = ToolDepiction(["capture", ""], PCAPReader, extension="pcap")  # Default tool - file_type ""
        self.pcap = ToolDepiction("capture-json", TSharkReader, extension="json")
        self.pcap_flow = ToolDepiction("exp-flow", SimpleFlowTool, extension="json")
        self.setup = ToolDepiction("setup", SetupCSVReader, extension="csv")
        self.shell_ps = ToolDepiction("shell-ps", ShellCommandPs)
        self.shell_ss = ToolDepiction("shell-ss", ShellCommandSs)
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
