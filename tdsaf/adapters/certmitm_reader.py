"""Certmitm reader"""

import json
from zipfile import ZipFile
from io import BufferedReader
from typing import Set, Tuple

from tdsaf.common.address import HWAddresses
from tdsaf.core.event_interface import EventInterface
from tdsaf.adapters.tools import SystemWideTool
from tdsaf.core.model import IoTSystem
from tdsaf.common.traffic import EvidenceSource, Evidence, IPFlow
from tdsaf.common.property import Properties
from tdsaf.common.verdict import Verdict


class CertMITMReader(SystemWideTool):
    """Read MITM logs created by certmitm"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("certmitm", system)
        self.tool.name = "certmitm tool"
        self.data_file_suffix = ".zip"

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        """Read log file"""
        evidence = Evidence(source)
        connections: Set[Tuple[str, str, str]] = set()

        # certmitm stores found issues in JSON format to errors.txt
        with ZipFile(data) as zip_file:
            for file in zip_file.filelist:
                if "errors.txt" in file.filename:
                    with zip_file.open(file.filename) as error_file:
                        for conn in error_file.read().decode("utf-8").rstrip().split("\n"):
                            conn = json.loads(conn)
                            connections.add((conn['client'], conn['destination']['ip'], conn['destination']['port']))

        for connection in connections:
            connection_source, target, port = connection
            flow = IPFlow.tcp_flow(
                HWAddresses.NULL.data, connection_source, 0,
                HWAddresses.NULL.data, target, int(port))
            flow.evidence = evidence
            Properties.MITM.put_verdict(flow.properties, Verdict.FAIL)
            interface.connection(flow)

        return True
