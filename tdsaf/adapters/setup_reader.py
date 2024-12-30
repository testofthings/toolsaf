"""Setup documentation reading"""
import csv
from typing import Dict

from io import BufferedReader, TextIOWrapper
from tdsaf.common.address import DNSName, EntityTag
from tdsaf.core.event_interface import EventInterface
from tdsaf.core.model import IoTSystem
from tdsaf.core.services import NameEvent
from tdsaf.adapters.tools import ToolAdapter
from tdsaf.common.traffic import Evidence, EvidenceSource


class SetupCSVReader(ToolAdapter):
    """Read setup documentation CSV files"""
    def __init__(self, system: IoTSystem):
        super().__init__("setup-doc", system)

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        # read csv file from data
        reader = csv.reader(TextIOWrapper(data))
        columns: Dict[str, int] = {}
        host_i = -1
        address_i = -1
        ev = Evidence(source)
        for row in reader:
            if not columns:
                columns = {c: i for i, c in enumerate(row)}
                host_i = columns.get("Host", -1)
                address_i = columns.get("Address", -1)
                continue
            if len(row) < len(columns):
                self.logger.warning("Row %s has less columns than %d", row, len(columns))
                continue
            host_tag = row[host_i].strip()
            ads = row[address_i].strip().split(", \t\n\r")
            if not host_tag or not ads:
                continue
            for a in ads:
                address = DNSName.name_or_ip(a)
                event = NameEvent(ev, None, tag=EntityTag(host_tag), address=address) # type: ignore[arg-type]
                interface.name(event)
        return True
