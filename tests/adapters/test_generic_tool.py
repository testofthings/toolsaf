"""Test the generic tool"""

import io
import json

import pytest

from toolsaf.adapters.generic_tool import GenericTool
from toolsaf.main import HTTP
from toolsaf.common.address import IPAddress
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import PropertyVerdictValue
from toolsaf.common.traffic import EvidenceSource
from tests.test_model import Setup


@pytest.mark.parametrize(
    "filename, json_dict, events",
    [
        ("no-data.json", {
            "results": []
        }, [
        ]),

        ("sample.json", {
            "tool": "Tool A",
            "description": "Testing the tester",
            "address": "1.2.3.4",
            "results": [
                {"key": "sample:key"},
                {"key": "sample:key", "verdict": "fail", "explanation": "Due"},
                {"claim": "sample:key2", "verdict": "Pass", "address": "Backend"},
            ]
        }, [
            ("sample:key", "Test_Device", Verdict.INCON, ""),
            ("sample:key", "Test_Device", Verdict.FAIL, "Due"),
            ("sample:key2", "Backend", Verdict.PASS, ""),
        ]),
    ]
)
def test_get_sub_element(filename, json_dict, events):
    setup = Setup()
    logger = setup.get_logger()
    tool = GenericTool(setup.get_system())

    source = EvidenceSource("source", "test")

    ip_addr = IPAddress.new("1.2.3.4")
    dev1 = setup.system.device("Test Device")
    dev1.new_address_(ip_addr)
    dev1 / HTTP
    dev2 = setup.system.backend()

    json_io = io.BytesIO(json.dumps(json_dict).encode())
    tool.process_file(json_io, filename, logger, source)

    assert "tool" not in json_dict or source.name == json_dict["tool"]
    assert "description" not in json_dict or source.description == json_dict["description"]

    log_events = logger.get_log()
    assert len(log_events) == len(json_dict["results"])
    for i, (key, add, verdict, exp) in enumerate(events):
        en = log_events[i]
        value = en.property_value[1]
        assert isinstance(value, PropertyVerdictValue)
        assert key == str(en.property_value[0])
        assert add == en.entity.get_system_address().get_parseable_value()
        # assert verdict == en.verdict
        assert verdict == value.verdict
        assert exp == value.explanation
