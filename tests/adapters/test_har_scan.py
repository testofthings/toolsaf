import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

from tdsaf.adapters.har_scan import HARScan
from tdsaf.main import HTTP
from tdsaf.core.model import Host
from tdsaf.common.property import PropertyKey
from tdsaf.common.verdict import Verdict
from tdsaf.common.traffic import EvidenceSource
from tests.test_model import Setup


@pytest.mark.parametrize(
    "spec, exp",
    [(Host, True), (HARScan, False)]
)
def test_filter_node(spec, exp):
    scan = HARScan(Setup().get_system())
    mock = MagicMock(spec=spec)
    assert scan.filter_node(mock) == exp


def test_process_node():
    setup = Setup()
    scan = HARScan(setup.get_system())

    browser = setup.system.browser("Browser")
    browser.cookies().set({
        "c1": (".test.com", "/", "desc"),
        "c2_*": (".test.com", "/", "desc"),
        "c3": (".test.com", "/", "desc")
    })

    backend = setup.system.backend("Backend").dns("abc.test.com")
    browser >> backend / HTTP

    source = EvidenceSource("nmap", "test")

    with Path("tests/samples/har/browser.json").open("rb") as f:
        scan.process_node(browser.entity, f, setup.get_inspector(), source)

        assert source.timestamp == datetime.strptime("2023-03-27T06:34:38.781Z", "%Y-%m-%dT%H:%M:%S.%fZ")

        assert len(browser.entity.components) == 1
        assert len(browser.entity.components[0].cookies) == 3
        cookie_props = browser.entity.components[0].properties

        assert cookie_props[PropertyKey("cookie", "c1")].verdict == Verdict.PASS
        assert cookie_props[PropertyKey("cookie", "c2_*")].verdict == Verdict.PASS
        assert cookie_props[PropertyKey("cookie", "c3")].verdict == Verdict.FAIL

        # property_address_update does nothing because of "if key.model and key not in s.properties:"
        # FIXME: HTTP redirect property check
