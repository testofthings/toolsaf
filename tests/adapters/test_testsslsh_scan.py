import pytest
import warnings
from pathlib import Path
from unittest.mock import MagicMock
warnings.filterwarnings("ignore", category=pytest.PytestCollectionWarning)

from toolsaf.adapters.testsslsh_scan import TestSSLScan
from toolsaf.common.address import EndpointAddress
from toolsaf.main import TLS
from toolsaf.core.model import Service
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict
from tests.test_model import Setup


@pytest.mark.parametrize(
    "spec, exp",
    [(Service, True), (Setup, False)]
)
def test_filter_node(spec, exp):
    scan = TestSSLScan(Setup().get_system())
    mock = MagicMock(spec=spec)
    assert scan.filter_node(mock) == exp


def test_process_endpoint_all_skipped():
    setup = Setup()
    scan = TestSSLScan(setup.get_system())

    backend = setup.system.backend("Backend")
    backend / TLS
    endpoint_addr = [addr for addr in setup.system.system.get_addresses() if isinstance(addr, EndpointAddress)][0]

    with Path("tests/samples/testssl/all-skipped.json").open("rb") as f:
        scan.process_endpoint(endpoint_addr, f, setup.get_inspector(), MagicMock())

        assert len(backend.entity.children) == 1
        service = backend.entity.children[0]

        assert len(service.properties) == 5
        assert service.properties[PropertyKey("check", "protocol", "tls")].verdict == Verdict.PASS
        assert service.properties[PropertyKey("check", "encryption")].verdict == Verdict.PASS


def test_process_endpoint():
    setup = Setup()
    scan = TestSSLScan(setup.get_system())

    backend = setup.system.backend("Backend")
    backend / TLS
    endpoint_addr = [addr for addr in setup.system.system.get_addresses() if isinstance(addr, EndpointAddress)][0]

    with Path("tests/samples/testssl/not-skipped.json").open("rb") as f:
        scan.process_endpoint(endpoint_addr, f, setup.get_inspector(), MagicMock())

        assert len(backend.entity.children) == 1
        service = backend.entity.children[0]

        assert len(service.properties) == 7
        assert service.properties[PropertyKey("testssl", "cipher_test1")].verdict == Verdict.FAIL
        assert service.properties[PropertyKey("testssl", "cipher_test2")].verdict == Verdict.FAIL
        assert service.properties[PropertyKey("check", "protocol", "tls")].verdict == Verdict.PASS
        assert service.properties[PropertyKey("check", "encryption")].verdict == Verdict.PASS
