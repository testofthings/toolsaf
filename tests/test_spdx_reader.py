import json
import pytest
import tempfile

from tdsaf.adapters.spdx_reader import SPDXJson
from tdsaf.main import ConfigurationException


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
