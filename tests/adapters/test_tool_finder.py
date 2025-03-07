import pytest
import warnings
warnings.filterwarnings("ignore", category=pytest.PytestCollectionWarning)

from toolsaf.adapters.tool_finder import ToolFinder
from toolsaf.adapters.android_manifest_scan import AndroidManifestScan
from toolsaf.adapters.censys_scan import CensysScan
from toolsaf.adapters.har_scan import HARScan
from toolsaf.adapters.certmitm_reader import CertMITMReader
from toolsaf.adapters.mobsf_scan import MobSFScan
from toolsaf.adapters.nmap_scan import NMAPScan
from toolsaf.adapters.github_releases import GithubReleaseReader
from toolsaf.adapters.ping_command import PingCommand
from toolsaf.adapters.pcap_reader import PCAPReader
from toolsaf.adapters.tshark_reader import TSharkReader
from toolsaf.adapters.tools import SimpleFlowTool
from toolsaf.adapters.setup_reader import SetupCSVReader
from toolsaf.adapters.shodan_scan import ShodanScan
from toolsaf.adapters.spdx_reader import SPDXReader
from toolsaf.adapters.ssh_audit_scan import SSHAuditScan
from toolsaf.adapters.testsslsh_scan import TestSSLScan
from toolsaf.adapters.vulnerability_reader import VulnerabilityReader
from toolsaf.adapters.web_checker import WebChecker
from toolsaf.adapters.zed_reader import ZEDReader
from tests.test_model import Setup


@pytest.mark.parametrize(
    "file_type, exp",
    [
        ("apk", AndroidManifestScan),
        ("censys", CensysScan),
        ("har", HARScan),
        ("http", WebChecker),
        ("certmitm", CertMITMReader),
        ("mobsf", MobSFScan),
        ("nmap", NMAPScan),
        ("github-releases", GithubReleaseReader),
        ("ping", PingCommand),
        ("capture", PCAPReader),
        ("capture-json", TSharkReader),
        ("exp-flow", SimpleFlowTool),
        ("setup", SetupCSVReader),
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
