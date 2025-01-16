from pathlib import Path
import pytest
from unittest.mock import MagicMock

from tdsaf.adapters.censys_scan import CensysScan
from tdsaf.core.model import Host
from tdsaf.common.property import Properties
from tdsaf.common.address import IPAddress
from tdsaf.common.verdict import Verdict
from tdsaf.main import SSH, HTTP
from tests.test_model import Setup


@pytest.mark.parametrize(
    "spec, exp",
    [(Host, True), (Setup, False)]
)
def test_filter_node(spec, exp):
    scan = CensysScan(Setup().get_system())
    mock = MagicMock(spec=spec)
    assert scan.filter_node(mock) == exp


def test_process_file():
    setup = Setup()
    scan = CensysScan(setup.get_system())

    backend = setup.system.backend("Test")
    endpoint= IPAddress.new("1.2.3.4")
    backend.new_address_(endpoint)
    backend / SSH
    backend / HTTP

    with Path("tests/samples/censys/backend.json").open("rb") as f:
        scan.process_endpoint(endpoint, f, setup.get_inspector(), MagicMock())
        assert len(backend.entity.children) == 5
        assert backend.entity.children[0].name == "SSH:22"
        assert backend.entity.children[0].properties[Properties.EXPECTED].verdict == Verdict.PASS

        assert backend.entity.children[1].name == "HTTP:80"
        assert backend.entity.children[1].properties[Properties.EXPECTED].verdict == Verdict.PASS
        # property_address_update always skips updating this property
        #assert backend.entity.children[1].properties[Properties.HTTP_REDIRECT].verdict == Verdict.PASS

        assert backend.entity.children[2].name == "TCP:81"
        assert backend.entity.children[2].properties[Properties.EXPECTED].verdict == Verdict.FAIL
        #assert Properties.HTTP_REDIRECT not in backend.entity.children[2].properties

        assert backend.entity.children[3].name == "UDP:22"
        assert backend.entity.children[3].properties[Properties.EXPECTED].verdict == Verdict.FAIL

        assert backend.entity.children[4].name == "TCP:1"
        assert backend.entity.children[4].properties[Properties.EXPECTED].verdict == Verdict.FAIL
