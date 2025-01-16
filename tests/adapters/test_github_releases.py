import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

from tdsaf.adapters.releases import ReleaseReader
from tdsaf.common.release_info import ReleaseInfo
from tdsaf.core.components import Software
from tests.test_model import Setup


@pytest.mark.parametrize(
    "spec, exp",
    [(Software, True), (Setup, False)]
)
def test_filter_node(spec, exp):
    scan = ReleaseReader(Setup().get_system())
    mock = MagicMock(spec=spec)
    assert scan.filter_component(mock) == exp


def test_process_component():
    setup = Setup()
    reader = ReleaseReader(setup.get_system())

    device = setup.system.device("Device")
    software = device.software().sw

    with Path("tests/samples/release/release.json").open("rb") as f:
        reader.process_component(software, f, setup.get_inspector(), MagicMock())

        assert len(software.properties) == 1
        info = software.properties[ReleaseInfo.PROPERTY_KEY]

        assert isinstance(info, ReleaseInfo)
        assert info.first_release == datetime(2025, 1, 10, 0, 0)
        assert info.latest_release == datetime(2025, 1, 14, 0, 0)
        assert info.latest_release_name == "v3.0"
        assert info.interval_days == 2
