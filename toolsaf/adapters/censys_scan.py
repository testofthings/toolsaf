"""Censys scan result tool"""

import argparse
from io import BufferedReader
import json
import logging
import pathlib

from censys.search import CensysHosts

from toolsaf.common.address import Protocol, EndpointAddress, AnyAddress
from toolsaf.core.event_interface import PropertyAddressEvent, EventInterface
from toolsaf.core.model import IoTSystem, NetworkNode, Host
from toolsaf.common.property import Properties
from toolsaf.adapters.tools import EndpointTool
from toolsaf.common.traffic import EvidenceSource, ServiceScan, Evidence, HostScan
from toolsaf.common.verdict import Verdict


class CensysScan(EndpointTool):
    """Censys scan tool"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("censys", ".json", system)
        self.tool.name = "Censys"

    def filter_node(self, node: NetworkNode) -> bool:
        return isinstance(node, Host)

    def process_endpoint(self, endpoint: AnyAddress, stream: BufferedReader, interface: EventInterface,
                         source: EvidenceSource) -> None:
        raw = json.load(stream)

        evidence = Evidence(source)

        host_services = set()
        for s in raw.get('services', []):
            service_name = s.get('service_name', '')
            protocol = Protocol.get_protocol(service_name.upper())
            transport = Protocol.protocol(s.get('transport_protocol'), Protocol.ANY)
            port = int(s['port'])

            self.logger.info("%s %s %d: %s", endpoint, transport, port, service_name)
            if service_name == "UNKNOWN":
                service_name = ""
            if service_name:
                service_name = f"{service_name} in port {port}"
            elif transport:
                service_name = f"{transport.value} {port}"
            addr = EndpointAddress(endpoint, transport, port)
            interface.service_scan(ServiceScan(evidence, addr, service_name))

            if protocol == Protocol.HTTP:
                status_code = s.get('http', {}).get('response', {}).get('status_code')
                if status_code == 301:
                    # 301 Permanently Moved
                    txt = f"{status_code} Permanently Moved"
                    ev = PropertyAddressEvent(evidence, addr, Properties.HTTP_REDIRECT.verdict(Verdict.PASS, txt))
                    interface.property_address_update(ev)
            host_services.add(addr)
        # other services were not seen
        interface.host_scan(HostScan(evidence, endpoint, host_services))


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--base-dir", default="censys", help="Base dir to create files into")
    arg_parser.add_argument("addresses", nargs="*", help="Address to resolve using from Censys service")
    args = arg_parser.parse_args()
    logging.basicConfig(format='%(message)s', level='INFO')
    base_dir = pathlib.Path(args.base_dir)

    m = CensysHosts()
    for a in args.addresses or []:
        save_file = base_dir / f"{a}.json"
        print(f"Scan and save {save_file.as_posix()}")
        info = m.view(a)
        with save_file.open("w") as f:
            json.dump(info, f, indent=4, sort_keys=True)
