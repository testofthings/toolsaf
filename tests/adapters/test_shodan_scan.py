import os
import json
import pytest
from pathlib import Path
from typing import Tuple, Optional
from unittest.mock import MagicMock, patch, mock_open

from toolsaf.adapters.shodan_scan import ShodanScan, ShodanScanner
from toolsaf.builder_backend import HostBackend
from toolsaf.main import ConfigurationException, HTTP
from toolsaf.common.address import IPAddress, Protocol, EndpointAddress
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey
from toolsaf.common.traffic import ServiceScan
from toolsaf.adapters.tools import IncorrectBatchFileExcpetion
from toolsaf.core.model import Service
from tests.test_model import Setup


# ShodanScan

@pytest.mark.parametrize(
    "entry, expected_protocol",
    [
        ({"_shodan": {"module": "any"}, "ssh": {"test": "test"}, "port": 1}, Protocol.SSH),
        ({"_shodan": {"module": "auto"}, "http": {"status": 200}, "ssl": {"test": "test"}, "port": 1}, Protocol.TLS),
        ({"_shodan": {"module": "auto"}, "http": {"status": 200}, "port": 1}, Protocol.HTTP),
        ({"_shodan": {"module": "mqtt"}, "port": 1}, Protocol.MQTT),
        ({"_shodan": {"module": "ssh"}, "port": 1}, Protocol.SSH),
        ({"_shodan": {"module": "unkown"}, "port": 1}, None)
    ]
)
def test_determine_protocol(entry, expected_protocol):
    scan = ShodanScan(Setup().get_system())
    assert scan.determine_protocol(entry) == expected_protocol


def test_determine_protocol_raises():
    scan = ShodanScan(Setup().get_system())
    with pytest.raises(IncorrectBatchFileExcpetion):
        scan.determine_protocol({})


@pytest.mark.parametrize(
    "entry, expected_port, expected_transport, expected_protocol",
    [
        ({"port": 80, "transport": "tcp", "_shodan": {"module": "http-simple"}, "http": {"status": 200}}, 80, Protocol.TCP, Protocol.HTTP),
        ({"port": 443, "transport": "tcp", "_shodan": {"module": "https-simple"}, "http": {"status": 200}, "ssl": {"test": "test"}}, 443, Protocol.TCP, Protocol.TLS),
        ({"port": 1883, "transport": "tcp", "_shodan": {"module": "mqtt"}}, 1883, Protocol.TCP, Protocol.MQTT),
        ({"port": 22, "transport": "udp", "_shodan": {"module": "ntp"}}, 22, Protocol.UDP, Protocol.NTP),
        ({"port": 1, "transport": "udp", "_shodan": {"module": "unknown"}}, 1, Protocol.UDP, Protocol.UDP)
    ]
)
def test_get_open_port_info(entry, expected_port, expected_transport, expected_protocol):
    scan = ShodanScan(Setup().get_system())
    port, transport, protocol = scan.get_open_port_info(entry)
    assert port == expected_port
    assert transport == expected_transport
    assert protocol == expected_protocol


def test_get_open_port_raises():
    scan = ShodanScan(Setup().get_system())
    with pytest.raises(IncorrectBatchFileExcpetion):
        scan.get_open_port_info({"port": 1})
    with pytest.raises(IncorrectBatchFileExcpetion):
        scan.get_open_port_info({"transport": 1})


def _mock_system(protocol: Optional[Protocol]=None) -> Tuple[ShodanScan, Service, HostBackend]:
    setup = Setup()
    scan = ShodanScan(setup.get_system())
    scan._interface = setup.get_inspector()
    scan._evidence = MagicMock()
    scan._key_set = set()

    ip_addr = IPAddress.new("1.2.3.4")
    backend = setup.system.backend("test").serve(HTTP)
    backend.new_address_(ip_addr)
    endpoint = EndpointAddress(ip_addr, Protocol.TCP, 80)
    if protocol:
        service = setup.get_inspector().service_scan(ServiceScan(scan._evidence, endpoint, protocol.value))
    else:
        service = setup.get_inspector().service_scan(ServiceScan(scan._evidence, endpoint, Protocol.SSH.value))

    return scan, service, backend


@pytest.mark.parametrize(
    "protocol, entry, exp_status_code, exp_verdict",
    [
        (Protocol.HTTP, {"http": {"status": 200}}, "200", Verdict.IGNORE),
        (Protocol.TLS, {"http": {"status": 404}}, "404", Verdict.IGNORE),
    ]
)
def test_add_http_status(protocol, entry, exp_status_code, exp_verdict):
    scan, service, _ = _mock_system(protocol)

    scan.add_http_status(protocol, entry, service)
    key_part = "http" if protocol == Protocol.HTTP else "https"
    assert service.properties[PropertyKey(scan.tool_label, key_part, "status", exp_status_code)].verdict == exp_verdict


def test_add_http_status_raises():
    scan, service, _ = _mock_system(Protocol.HTTP)
    with pytest.raises(IncorrectBatchFileExcpetion):
        scan.add_http_status(Protocol.HTTP, {"http": {}}, service)


@pytest.mark.parametrize(
    "vulnerabilities, exp_verdict",
    [
        ({"CVE-2021-12345": {"summary": "test", "cvss": 5.1}}, Verdict.FAIL),
        ({"CVE-2021-12345": {"summary": "test", "cvss": 5.1}, "CVE-2021-67890": {"summary": "test", "cvss": 5.1}}, Verdict.FAIL),
    ]
)
def test_add_vulnerabilities(vulnerabilities, exp_verdict):
    scan, service, _ = _mock_system()

    scan.add_vulnerabilities(vulnerabilities, service)
    for vulnerability in vulnerabilities:
        assert service.properties[PropertyKey(scan.tool_label, vulnerability)].verdict == exp_verdict
        assert service.properties[PropertyKey(scan.tool_label, vulnerability)].explanation == "CVSS: 5.1, test"


@pytest.mark.parametrize(
    "vulnerabilities",
    [
        ({"test": {}}),
        ({"test": {"cvss": 1.0}}),
        ({"test": {"summary": "test summary"}})
    ]
)
def test_add_vulnerabilities_raises(vulnerabilities):
    scan, service, _  = _mock_system()
    with pytest.raises(IncorrectBatchFileExcpetion):
        scan.add_vulnerabilities(vulnerabilities, service)


@pytest.mark.parametrize(
    "opts, exp_verdict, exp_comment",
    [
        ({"heartbleed": "2025/01/01 00:00:00 - SAFE\n"}, Verdict.PASS, "SAFE"),
        ({"heartbleed": "2025/01/01 00:00:00 - VULNERABLE\n"}, Verdict.FAIL, "VULNERABLE"),
    ]
)
def test_add_heartbleed(opts, exp_verdict, exp_comment):
    scan, service, _ = _mock_system()

    scan.add_heartbleed(opts, service)
    assert service.properties[PropertyKey(scan.tool_label, "heartbleed")].verdict == exp_verdict
    assert service.properties[PropertyKey(scan.tool_label, "heartbleed")].explanation == exp_comment


@pytest.mark.parametrize(
    "cpe23, exp_product, exp_version",
    [
        ("cpe:2.3:a:example:software:1.0", "software", "1.0"),
        ("cpe:2.3:a:example:software:", "software", None),
        ("cpe:2.3:a:example:software", "software", None),
        ("cpe:2.3:a:example:software:2.0:extra", "software", "2.0"),
    ]
)
def test_parse_cpe23(cpe23, exp_product, exp_version):
    scan = ShodanScan(Setup().get_system())
    product, version = scan.parse_cpe23(cpe23)
    assert product == exp_product
    assert version == exp_version


@pytest.mark.parametrize(
    "cpe23, exp_verdict, exp_comment",
    [
        (["cpe:2.3:a:example:software:1.0"], Verdict.FAIL, ["v1.0, Shodan CPE 2.3"]),
        (["cpe:2.3:a:example:software:1.0", "cpe:2.3:a:example:software2:2.0"], Verdict.FAIL, ["v1.0, Shodan CPE 2.3", "v2.0, Shodan CPE 2.3"]),
        (["cpe:2.3:a:example:software3"], Verdict.PASS, ["Shodan CPE 2.3"]),
    ]
)
def test_add_cpes(cpe23, exp_verdict, exp_comment):
    scan, service, backend = _mock_system()
    backend.software("test sw").sbom(["software3"])

    scan.add_cpes(cpe23, service)
    for i, entry in enumerate(cpe23):
        product, _ = scan.parse_cpe23(entry)
        assert service.parent.components[0].properties[PropertyKey("component", product)].verdict == exp_verdict
        assert service.parent.components[0].properties[PropertyKey("component", product)].explanation == exp_comment[i]


def test_process_file():
    scan, _, _ = _mock_system()

    data = json.dumps({
        "data": [
            {
                "_shodan": {"module": "http-simple"},
                "port": 80, "transport": "tcp", "http": {"status": 200},
                "vulns": {"CVE-2021-12345": {"cvss": 1.0, "summary": "test"}},
                "opts": {"heartbleed": "2025/01/01 00:00:00 - SAFE\n"},
                "cpe23": ["cpe:2.3:a:example:software:1.0"],
                "ip_str": "1.2.3.4"
            }
        ]
    })

    with patch("builtins.open", mock_open(read_data=data)):
        with open("test.json", "r") as file:
            scan.process_file(file, "test-1.2.3.4.json", scan._interface, MagicMock())
            service = scan.system.children[0]
            assert len(service.children[0].properties) > 2


def test_process_file_incorrect_filename():
    scan, _, _ = _mock_system()
    data = json.dumps({
        "data": [{"tags": []}]
    })
    with patch("builtins.open", mock_open(read_data=data)):
        with open("test.json", "r") as file:
            with pytest.raises(IncorrectBatchFileExcpetion):
                scan.process_file(file, "test-example.com.json", scan._interface, MagicMock())


# ShodanScanner

ARGS = [
    ("iplookup", "ip_lookup"),
    ("dnslookup", "dns_lookup"),
    ("credits", "display_remaining_credits"),
    ("unknown", None)
]


def test_get_api_key():
    with patch("os.getenv", return_value=""):
        with pytest.raises(AssertionError):
            ShodanScanner(api_key=os.getenv("SHODAN_API_KEY"))

    with patch("os.getenv", return_value="test"):
        scanner = ShodanScanner(api_key=os.getenv("SHODAN_API_KEY"))
        assert scanner.api.api_key == "test"


@pytest.mark.parametrize(
    "argv, exp",
    [
        (["", ARGS[0][0]], (Path("shodan"), ARGS[0][0], [])),
        (["", ARGS[1][0]], (Path("shodan"), ARGS[1][0], [])),
        (["", ARGS[2][0], "ip1", "ip2"], (Path("shodan"), ARGS[2][0], ["ip1", "ip2"])),
        (["", "--base-dir", "test", ARGS[0][0], "ip1", "ip2"], (Path("test"), ARGS[0][0], ["ip1", "ip2"])),
    ])
def test_get_args(argv, exp):
    scanner = ShodanScanner("api_key")
    with patch("argparse._sys.argv", argv):
        scanner.get_args()
        assert scanner.base_dir == exp[0]
        assert scanner.command == exp[1]
        assert scanner.addresses == exp[2]


def test_perform_command():
    scanner = ShodanScanner("api_key")
    scanner.ip_lookup = MagicMock()
    scanner.dns_lookup = MagicMock()
    scanner.display_remaining_credits = MagicMock()

    for cmd, method in ARGS:
        scanner.command = cmd
        if method:
            scanner.perform_command()
            getattr(scanner, method).assert_called_once()
        else:
            with pytest.raises(ConfigurationException):
                scanner.perform_command()


def test_display_remaining_credits():
    scanner = ShodanScanner("api_key")
    scanner.api.info = MagicMock(return_value={"credits": 100})
    with patch("builtins.print") as mock_print:
        scanner.display_remaining_credits()
        mock_print.assert_called_with(json.dumps({"credits": 100}, indent=4))
