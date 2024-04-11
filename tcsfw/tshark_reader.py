"""Tshark JSON reading tool"""

import argparse
import datetime
from io import BytesIO
import json
import pathlib
from typing import Dict, Optional, Self

from tcsfw.address import HWAddress
from tcsfw.event_interface import EventInterface
from tcsfw.inspector import Inspector
from tcsfw.model import IoTSystem
from tcsfw.tools import BaseFileCheckTool
from tcsfw.traffic import EvidenceSource, BLEAdvertisementFlow, Evidence


class TSharkReader(BaseFileCheckTool):
    """Read in TShark JSON input"""
    def __init__(self, system: IoTSystem):
        super().__init__("pcap-tshark", system)
        self.tool.name = "TShark PCAP reader"
        self.data_file_suffix = ".json"
        # current frame
        self.source: Optional[EvidenceSource] = None

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> Self:
        # not for large files, very Python-style
        raw = json.load(data)
        self.source = source
        self.parse(raw, interface)
        return self

    def read(self, data_file: pathlib.Path, interface: EventInterface, source: EvidenceSource):
        """Read PCAP file"""
        with data_file.open("r") as f:
            return self.process_file(f, data_file.name, interface, source)

    def parse(self, raw: Dict, interface: EventInterface):
        """Parse JSON"""
        ads = set()
        for nr, sf in enumerate(raw):
            fl = sf["_source"]["layers"]
            pf = fl.get("bthci_evt")
            if pf:
                ev = Evidence(self.source, f":{nr + 1}")
                r_time = float(fl["frame"]["frame.time_epoch"])
                self.source.timestamp = datetime.datetime.fromtimestamp(round(r_time))
                ad = self.parse_hvc_event(pf, interface, ev)
                ads.add(ad)

    def parse_hvc_event(self, raw: Dict, interface: EventInterface, evidence: Evidence) -> HWAddress:
        """Parse HVC event"""
        bd_addr = raw['bthci_evt.bd_addr']
        ev_code = int(raw['bthci_evt.le_advts_event_type'], 16)
        add = HWAddress.new(bd_addr)  # FIXME: We need different HW address space for BL and Eth!
        flow = BLEAdvertisementFlow(evidence, add, ev_code)
        interface.connection(flow)
        return add



if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("file", help="File to read")
    f_name = arg_parser.parse_args().file
    reader = TSharkReader(IoTSystem())
    reader.read(pathlib.Path(f_name), Inspector(reader.system), EvidenceSource(reader.tool.name))
    print(reader.interface)
