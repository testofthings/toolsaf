import json
import tempfile
import pytest
from unittest.mock import MagicMock

from tdsaf.builder_backend import SoftwareBackend
from tdsaf.main import ConfigurationException
from tdsaf.common.property import PropertyKey
from tdsaf.common.verdict import Verdict


def test_sbom_no_input():
    sb = SoftwareBackend(MagicMock(), "test")
    with pytest.raises(ConfigurationException):
        sb.sbom()


def test_sbom_components_list():
    sb = SoftwareBackend(MagicMock(), "test")
    sb.sbom(["c1", "c2"])
    assert len(sb.sw.components) == 2
    assert len(sb.sw.properties) == 2
    assert sb.sw.properties[
        PropertyKey("component", "c1")
    ].verdict == Verdict.INCON
    assert sb.sw.properties[
        PropertyKey("component", "c2")
    ].verdict == Verdict.INCON


def test_sbom_file():
    sb = SoftwareBackend(MagicMock(), "test")

    with pytest.raises(ConfigurationException):
        sb.sbom(file_path="test.json") # No file found

    with pytest.raises(ConfigurationException):
        sb.sbom(file_path="test.txt") # Not JSON

    with tempfile.NamedTemporaryFile(delete=True, mode="w+", suffix=".json") as tmp:
        json.dump({
            "packages": [
                { "name": "package-1", "versionInfo": "1.0" },
                { "name": "package-2", "versionInfo": "2.1.0" }
            ]
        }, tmp)
        tmp.seek(0)

        sb.sbom(file_path=tmp.name)
        assert len(sb.sw.components) == 2
        assert sb.sw.components["package-1"].version == "1.0"
        assert sb.sw.components["package-2"].version == "2.1.0"

        assert len(sb.sw.properties) == 2
        assert sb.sw.properties[
            PropertyKey("component", "package-1")
        ].verdict == Verdict.INCON
        assert sb.sw.properties[
            PropertyKey("component", "package-2")
        ].verdict == Verdict.INCON
