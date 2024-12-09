import io
import json
import pytest
import tempfile
from unittest.mock import MagicMock

from tdsaf.adapters.spdx_reader import SPDXJson, SPDXReader
from tdsaf.core.components import Software, SoftwareComponent
from tdsaf.common.property import PropertyKey
from tdsaf.main import ConfigurationException
from tdsaf.common.verdict import Verdict
from tests.test_model import Setup


def test_spdx_json_read():
    with tempfile.NamedTemporaryFile(delete=True, mode="w+") as tmp:
        json.dump({
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "package-1",
                    "versionInfo": "1.0",
                    "licenseConcluded": "MIT"
                },
                {
                    "name": "package-2",
                    "versionInfo": "2.1.0",
                    "licenseConcluded": "MIT"
                },
                {
                    "name": "package-3",
                    "licenseConcluded": "MIT"
                }
            ]
        }, tmp)
        tmp.seek(0)

        components = SPDXJson(file=tmp).read()
        assert len(components) == 3
        assert components[0].name == "package-1"
        assert components[0].version == "1.0"
        assert components[1].name == "package-2"
        assert components[1].version == "2.1.0"
        assert components[2].name == "package-3"
        assert components[2].version == ""


def test_spdx_json_read_apk_kludge():
    with tempfile.NamedTemporaryFile(delete=True, mode="w+") as tmp:
        json.dump({
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "package-1.apk",
                    "versionInfo": "1.0",
                    "licenseConcluded": "MIT"
                },
                {
                    "name": "package-2",
                    "versionInfo": "2.1.0",
                    "licenseConcluded": "MIT"
                }
            ]
        }, tmp)
        tmp.seek(0)

        components = SPDXJson(file=tmp).read()
        assert len(components) == 1
        assert components[0].name == "package-2"
        assert components[0].version == "2.1.0"


def test_spdx_json_read_incorrect_json():
    with tempfile.NamedTemporaryFile(delete=True, mode="w+") as tmp:
        json.dump({
            "packages": [
                { "versionInfo": "1.0","licenseConcluded": "MIT" }
            ]
        }, tmp)
        tmp.seek(0)

        with pytest.raises(ConfigurationException):
            SPDXJson(file=tmp).read()

    with tempfile.NamedTemporaryFile(delete=True, mode="w+") as tmp:
        json.dump({
            "pckts": [
                { "versionInfo": "1.0","licenseConcluded": "MIT" }
            ]
        }, tmp)
        tmp.seek(0)

        with pytest.raises(ConfigurationException):
            SPDXJson(file=tmp).read()


def _get_json_data(packages: list[dict]) -> io.BytesIO:
    data = io.BytesIO()
    data.write(json.dumps({
        "packages": packages
    }).encode("utf-8"))
    data.seek(0)
    return data


def test_process_component():
    setup = Setup()
    reader = SPDXReader(setup.get_system())

    sw = Software(MagicMock())
    sw.components["c1"] = SoftwareComponent("c1", "1.0")
    sw.components["c2"] = SoftwareComponent("c2", "1.0")

    data = _get_json_data(packages=[
        {"name": "c1", "versionInfo": "1.0"},
        {"name": "c2", "versionInfo": "1.0"}
    ])

    # Incon pois
    assert reader.process_component(sw, data, setup.get_inspector(), MagicMock())
    assert sw.properties[PropertyKey("component", "c1")].verdict == Verdict.PASS
    assert sw.properties[PropertyKey("component", "c2")].verdict == Verdict.PASS


def test_process_component_in_statement_not_in_data():
    setup = Setup()
    reader = SPDXReader(setup.get_system())

    sw = Software(MagicMock())
    sw.components["c1"] = SoftwareComponent("c1", "1.0")

    data = _get_json_data(packages=[])

    assert reader.process_component(sw, data, setup.get_inspector(), MagicMock())
    assert sw.properties[PropertyKey("component", "c1")].verdict == Verdict.FAIL


def test_process_component_not_in_statement_in_data():
    setup = Setup()
    reader = SPDXReader(setup.get_system())

    sw = Software(MagicMock())

    data = _get_json_data(packages=[
        {"name": "c1", "versionInfo": "1.0"}
    ])

    assert reader.process_component(sw, data, setup.get_inspector(), MagicMock())
    assert sw.properties[PropertyKey("component", "c1")].verdict == Verdict.FAIL
