from pathlib import Path
from datetime import datetime

from toolsaf.adapters.zed_reader import ZEDReader
from toolsaf.common.traffic import EvidenceSource
from toolsaf.main import TLS
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict
from tests.test_model import Setup


def test_process_file_no_alerts():
    setup = Setup()
    reader = ZEDReader(setup.get_system())

    backend = setup.system.backend("Backend").dns("example.com")
    backend / TLS
    source = EvidenceSource("zap", "test")

    with Path("tests/samples/zap/backend-no-alerts.json").open("rb") as f:
        reader.process_file(f, "", setup.get_inspector(), source)

        assert source.timestamp == datetime.strptime("Wed, 1 Jan 2025 01:01:01", "%a, %d %b %Y %H:%M:%S")
        props = backend.entity.children[0].properties
        assert len(props) == 3
        assert PropertyKey("check", "web") in props
        assert PropertyKey("check", "protocol", "http", "best-practices") in props
        assert backend.entity.get_verdict({}) == Verdict.PASS


def test_process_file():
    setup = Setup()
    reader = ZEDReader(setup.get_system())

    backend = setup.system.backend("Backend").dns("example.com")
    backend / TLS
    source = EvidenceSource("zap", "test")

    with Path("tests/samples/zap/backend.json").open("rb") as f:
        reader.process_file(f, "", setup.get_inspector(), source)

        assert source.timestamp == datetime.strptime("Wed, 1 Jan 2025 01:01:01", "%a, %d %b %Y %H:%M:%S")
        props = backend.entity.children[0].properties
        assert len(props) == 4
        assert props[PropertyKey("zed", "1234")].verdict == Verdict.FAIL
        assert PropertyKey("check", "web") in props
        assert PropertyKey("check", "protocol", "http", "best-practices") in props
        assert backend.entity.get_verdict({}) == Verdict.FAIL
