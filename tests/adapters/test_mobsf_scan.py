import pytest
from unittest.mock import MagicMock

from toolsaf.adapters.mobsf_scan import MobSFScan
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyKey
from toolsaf.core.event_interface import PropertyEvent
from tests.test_model import Setup


@pytest.mark.parametrize(
    "scan_json, exp_result",
    [
        ({}, []),
        ({"certificate_analysis": {}}, []),
        ({"certificate_analysis": {"certificate_findings": []}}, []),
        (
            {"certificate_analysis": {"certificate_findings":
                [("info", "test", "test")]
            }},
            []
        ),
        (
            {"certificate_analysis": {"certificate_findings":
                [("warning", "test", "test"), ("high", "test desc", "test title"), ("info", "1", "2")]
            }},
            [
                PropertyEvent(MagicMock(), None, PropertyKey("mobsf", "cert", "test").verdict(Verdict.FAIL, "test")),
                PropertyEvent(MagicMock(), None, PropertyKey("mobsf", "cert", "test-title").verdict(Verdict.FAIL, "test desc"))
            ]
        )
    ]
)
def test_get_certificate_finding_events(scan_json, exp_result):
    msf = MobSFScan(Setup().get_system())
    result = msf._get_certificate_finding_events(MagicMock(), None, scan_json)
    assert len(result) == len(exp_result)
    for i, entry in enumerate(result):
        assert entry.key_value == exp_result[i].key_value


@pytest.mark.parametrize(
    "scan_json, exp_result",
    [
        ({}, None),
        ({"secrets": []}, None),
        (
            {"secrets": [1,2,3]},
            PropertyEvent(MagicMock(), None, PropertyKey("mobsf", "secrets").verdict(Verdict.FAIL, "Found 3 possible hardocded secrets"))
        )
    ]
)
def test_get_possible_hardcoded_secrets_event(scan_json, exp_result):
    msf = MobSFScan(Setup().get_system())
    result = msf._get_possible_hardcoded_secrets_event(MagicMock(), None, scan_json)
    if exp_result is not None:
        assert result.key_value == exp_result.key_value
    else:
        assert result == exp_result