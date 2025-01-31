import pytest
from pathlib import Path
from unittest.mock import MagicMock

from toolsaf.adapters.ssh_audit_scan import SSHAuditScan
from toolsaf.common.address import Protocol, EndpointAddress
from toolsaf.main import SSH
from toolsaf.core.model import Service
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict
from tests.test_model import Setup


@pytest.mark.parametrize(
    "spec, protocol, exp",
    [
        (Service, Protocol.SSH, True),
        (Service, Protocol.HTTP, False),
        (Setup, Protocol.SSH, False)
    ]
)
def test_filter_node(spec, protocol, exp):
    scan = SSHAuditScan(Setup().get_system())
    mock = MagicMock(spec=spec)
    mock.protocol = protocol
    assert scan.filter_node(mock) == exp


def _del_key(key: str, name: str) -> PropertyKey:
    return PropertyKey(
        "ssh-audit", "del", key, name
    )

def _chg_key(key: str, name: str) -> PropertyKey:
    return PropertyKey(
        "ssh-audit", "chg", key, name
    )

def _key(*keys: str) -> PropertyKey:
    return PropertyKey(*keys)

def test_process_endpoint():
    setup = Setup()
    scan = SSHAuditScan(setup.get_system())

    device = setup.system.device("Device")
    backend = setup.system.backend("Backend")
    backend >> device / SSH
    endpoint_addr = [addr for addr in setup.system.system.get_addresses() if isinstance(addr, EndpointAddress)][0]

    with Path("tests/samples/ssh-audit/backend.json").open("rb") as f:
        scan.process_endpoint(endpoint_addr, f, setup.get_inspector(), MagicMock())

        assert len(device.entity.children) == 1
        ssh_props = device.entity.children[0].properties

        assert len(ssh_props) == 11

        assert ssh_props[PropertyKey("ssh-audit", "cve-123")].verdict == Verdict.FAIL
        assert ssh_props[PropertyKey("ssh-audit", "cve-123")].explanation == "example description"
        assert ssh_props[PropertyKey("ssh-audit", "cve-456")].verdict == Verdict.FAIL
        assert ssh_props[PropertyKey("ssh-audit", "cve-456")].explanation == "test"

        assert ssh_props[_del_key("kex", "name1")].verdict == Verdict.FAIL
        assert ssh_props[_del_key("key", "name2")].verdict == Verdict.FAIL
        assert ssh_props[_chg_key("key", "name3")].verdict == Verdict.FAIL

        assert ssh_props[_key("check", "protocol", "ssh")].verdict == Verdict.PASS
        assert ssh_props[_key("check", "encryption")].verdict == Verdict.PASS
        assert ssh_props[_key("check", "auth")].verdict == Verdict.PASS
