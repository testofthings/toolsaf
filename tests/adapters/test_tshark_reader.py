from datetime import datetime
from pathlib import Path

from toolsaf.adapters.tshark_reader import TSharkReader
from toolsaf.main import BLEAdvertisement
from toolsaf.common.verdict import Verdict
from toolsaf.common.address import HWAddress
from toolsaf.common.traffic import EvidenceSource
from tests.test_model import Setup


def test_process_file():
    setup = Setup()
    reader = TSharkReader(setup.get_system())
    source = EvidenceSource("tshark", "test")

    hw_addr = HWAddress("aa:aa:aa:aa:aa:aa")
    device = setup.system.device("Device")
    device.new_address_(hw_addr)

    ble_ad = setup.system.broadcast(BLEAdvertisement(event_type=0x01))
    device >> ble_ad

    with Path("tests/samples/tshark/capture.json").open("rb") as f:
        reader.process_file(f, "", setup.get_inspector(), source)

        assert source.timestamp == datetime.fromtimestamp(round(float("1875944139.865893000")))

        connections = list(setup.get_system().connections.values())
        assert len(connections) == 3

        # Everything OK
        assert connections[0].source == device.entity
        assert connections[0].target.name == "BLE Ad:1"
        assert connections[0].get_verdict({}) == Verdict.PASS

        # Different event_type
        assert connections[1].source == device.entity
        assert connections[1].target.name == "BLE Ads"
        assert connections[1].get_verdict({}) == Verdict.FAIL

        # Unknown device
        assert HWAddress("bb:bb:bb:bb:bb:bb") in connections[2].source.addresses
        assert connections[2].target.name == "BLE Ad:1"
        assert connections[2].get_verdict({}) == Verdict.INCON
