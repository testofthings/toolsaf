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

    with pytest.raises(ConfigurationException): # No column_num given
        sb.sbom(file="test.csv")

    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(b"c1\nc2\nc3")
        tmp.seek(0)

        sb.sbom(file=tmp.name, column_num=0)
        assert len(sb.sw.components) == 3
        assert len(sb.sw.properties) == 3
        assert sb.sw.properties[
            PropertyKey("component", "c1")
        ].verdict == Verdict.INCON
        assert sb.sw.properties[
            PropertyKey("component", "c3")
        ].verdict == Verdict.INCON