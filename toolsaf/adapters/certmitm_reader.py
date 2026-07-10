"""Certmitm reader"""

import json
from zipfile import ZipFile
from io import BufferedReader
from typing import Set, Tuple, Dict, Any, cast

from toolsaf.adapters.tools import SystemWideTool
from toolsaf.core.event_interface import EventInterface, PropertyEvent
from toolsaf.core.model import IoTSystem, Host, Service
from toolsaf.common.basics import ConnectionType
from toolsaf.common.address import HWAddresses, DNSName, AnyAddress
from toolsaf.common.traffic import EvidenceSource, Evidence, IPFlow
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict


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
        seen_addresses: Set[AnyAddress] = set()

        # certmitm stores found issues in JSON format to errors.txt
        with ZipFile(data) as zip_file:
            for file in zip_file.filelist:
                if "errors.txt" in file.filename:
                    with zip_file.open(file.filename) as error_file:
                        for conn_str in error_file.read().decode("utf-8").rstrip().split("\n"):
                            conn_json = cast(Dict[str, Any], json.loads(conn_str))
                            connections.add(
                                (conn_json['client'], conn_json['destination']['ip'], conn_json['destination']['port'])
                            )

        for connection in connections:
            connection_source, target, port = connection
            flow = IPFlow.tcp_flow(
                HWAddresses.NULL.data, connection_source, 0,
                HWAddresses.NULL.data, target, int(port))
            flow.evidence = evidence
            PropertyKey("certmitm").put_verdict(flow.properties, Verdict.FAIL)
            interface.connection(flow)

        # Workaround for showing that certmitm was used
        with ZipFile(data) as zip_file:
            for file in zip_file.filelist:
                if "certificates" in file.filename and not file.filename.endswith("/"):
                    identifier = file.filename.split("/")[-1].split("_")[0]
                    address = DNSName.name_or_ip(identifier)
                    if isinstance(address, DNSName):
                        DNSName.validate(identifier)
                    if address in seen_addresses:
                        continue
                    seen_addresses.add(address)
                    if (endpoint := self.system.find_endpoint(address)):
                        if not isinstance(endpoint, Host):
                            continue
                        for endpoint_connection in endpoint.connections:
                            if not isinstance(endpoint_connection.target, Service):
                                continue
                            key = PropertyKey(self.tool_label)
                            if endpoint_connection.con_type == ConnectionType.ENCRYPTED \
                            and key not in endpoint_connection.properties:
                                ev = PropertyEvent(evidence, endpoint_connection, key.verdict(Verdict.PASS))
                                interface.property_update(ev)

        return True
