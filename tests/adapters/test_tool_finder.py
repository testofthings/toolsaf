import pytest
import warnings
warnings.filterwarnings("ignore", category=pytest.PytestCollectionWarning)

from tdsaf.adapters.tool_finder import ToolFinder
from tdsaf.adapters.android_manifest_scan import AndroidManifestScan
from tdsaf.adapters.censys_scan import CensysScan
from tdsaf.adapters.har_scan import HARScan
from tdsaf.adapters.certmitm_reader import CertMITMReader
from tdsaf.adapters.nmap_scan import NMAPScan
from tdsaf.adapters.github_releases import GithubReleaseReader
from tdsaf.adapters.ping_command import PingCommand
from tdsaf.adapters.pcap_reader import PCAPReader
from tdsaf.adapters.tshark_reader import TSharkReader
from tdsaf.adapters.tools import SimpleFlowTool
from tdsaf.adapters.setup_reader import SetupCSVReader
from tdsaf.adapters.shell_commands import ShellCommandPs, ShellCommandSs
from tdsaf.adapters.shodan_scan import ShodanScan
from tdsaf.adapters.spdx_reader import SPDXReader
from tdsaf.adapters.ssh_audit_scan import SSHAuditScan
from tdsaf.adapters.testsslsh_scan import TestSSLScan
from tdsaf.adapters.vulnerability_reader import VulnerabilityReader
from tdsaf.adapters.web_checker import WebChecker
from tdsaf.adapters.zed_reader import ZEDReader
from tests.test_model import Setup


@pytest.mark.parametrize(
    "file_type, exp",
    [
        ("apk", AndroidManifestScan),
        ("censys", CensysScan),
        ("har", HARScan),
        ("http", WebChecker),
        ("certmitm", CertMITMReader),
        ("nmap", NMAPScan),
        ("github-releases", GithubReleaseReader),
        ("ping", PingCommand),
        ("capture", PCAPReader),
        ("capture-json", TSharkReader),
        ("exp-flow", SimpleFlowTool),
        ("setup", SetupCSVReader),
        ("shell-ps", ShellCommandPs),
        ("shell-ss", ShellCommandSs),
        ("shodan", ShodanScan),
        ("spdx", SPDXReader),
        ("ssh-audit", SSHAuditScan),
        ("testssl", TestSSLScan),
        ("blackduck-vulnerabilities", VulnerabilityReader),
        ("zap", ZEDReader),
    ]
)
def test_by_file_type(file_type, exp):
    result = ToolFinder.by_file_type(file_type)
    assert len(result.tools) == 1
    tool = result.create_tool(Setup().get_system())
    assert isinstance(tool, exp)


def test_by_file_type_exception():
    with pytest.raises(ValueError):
        ToolFinder.by_file_type("not-found")
