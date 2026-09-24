"""Certmitm reader"""

import json
from zipfile import ZipFile
from io import BufferedReader
from typing import Dict, List, Set, Tuple, Any, cast

from toolsaf.adapters.tools import SystemWideTool
from toolsaf.core.event_interface import EventInterface, PropertyEvent
from toolsaf.core.model import Addressable, IoTSystem, Host, Service
from toolsaf.common.address import HWAddresses, DNSName, AnyAddress, Protocol
from toolsaf.common.traffic import EvidenceSource, Evidence, IPFlow
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.common.verdict import Verdict


class CertMITMReader(SystemWideTool):
    """Read MITM logs created by certmitm"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("certmitm", system)
        self.tool.name = "Certmitm tool"
        self.data_file_suffix = ".zip"

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        """Read log file"""
        evidence = Evidence(source)
        # dict used as an insertion-ordered set to keep connections in the order they were read
        connections: Dict[Tuple[str, str, str, str], Any] = {}
        seen_addresses: Set[AnyAddress] = set()

        # certmitm stores found issues in JSON format to errors.txt
        with ZipFile(data) as zip_file:
            for file in zip_file.filelist:
                if "errors.txt" in file.filename:
                    with zip_file.open(file.filename) as error_file:
                        for conn_str in error_file.read().decode("utf-8").rstrip().split("\n"):
                            conn_json = cast(Dict[str, Any], json.loads(conn_str))
                            connections[
                                (conn_json['client'],
                                 conn_json['destination']['ip'],
                                 conn_json['destination']['port'],
                                 conn_json['testcase'],
                                )
                            ] = conn_json

        failures: Dict[Addressable, List[PropertyKey]] = {}
        for connection in connections:
            connection_source, target, port, testcase = connection
            flow = IPFlow.tcp_flow(
                HWAddresses.NULL.data, connection_source, 0,
                HWAddresses.NULL.data, target, int(port))
            flow.evidence = evidence
            conn = interface.connection(flow)
            if conn:
                # Assigning the failure event to the target TLS service, not as connection property as earlier
                exp = f"MITM vulnerability {connection_source} -> {target}:{port} (Certmitm: {testcase})"
                prop = PropertyKey(self.tool_label, testcase)
                ev = PropertyEvent(evidence, conn.target, prop.verdict(Verdict.FAIL, exp))
                failures.setdefault(conn.target, []).append(ev.key_value[0])
                interface.property_update(ev)

        best_practices_key = Properties.PROTOCOL.append_key("tls").append_key("best-practices")
        for service, events in failures.items():
            # TLS best pratice property set event per failing service
            bp = best_practices_key.value_set(set(events), "MITM attack successful")
            interface.property_update(PropertyEvent(evidence, service, bp))


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
                            service = endpoint_connection.target
                            if not isinstance(service, Service) or service.protocol != Protocol.TLS:
                                continue
                            if service in failures:
                                continue  # this has failed
                            ev = PropertyEvent(
                                evidence, service,
                                best_practices_key.verdict(Verdict.PASS, "MITM attack not successful"))
                            interface.property_update(ev)

        return True
