import argparse
from io import BytesIO
import json
import logging
import pathlib
from typing import List

from censys.search import CensysHosts

from tcsfw.address import Protocol, EndpointAddress, AnyAddress
from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyAddressEvent, EventInterface
from tcsfw.model import IoTSystem, NetworkNode, Service, Host
from tcsfw.property import Properties, PropertyKey
from tcsfw.tools import EndpointCheckTool
from tcsfw.traffic import EvidenceSource, ServiceScan, Evidence, HostScan
from tcsfw.verdict import Verdict


class CensysScan(EndpointCheckTool):
    def __init__(self, system: IoTSystem):
        super().__init__("censys", ".json", system)
        self.tool.name = "Censys"

    def _filter_node(self, node: NetworkNode) -> bool:
        return isinstance(node, Host)

    def process_stream(self, address: AnyAddress, stream: BytesIO, interface: EventInterface, source: EvidenceSource):
        raw = json.load(stream)

        evidence = Evidence(source)

        host_services = set()
        for s in raw.get('services', []):
            service_name = s.get('service_name', '')
            protocol = Protocol.get_protocol(service_name.upper())
            transport = Protocol.get_protocol(s.get('transport_protocol'), Protocol.ANY)
            port = int(s['port'])

            self.logger.info("%s %s %d: %s", address, transport, port, service_name)
            if service_name == "UNKNOWN":
                service_name = ""
            if service_name:
                service_name = f"{service_name} in port {port}"
            elif transport:
                service_name = f"{transport.value} {port}"
            addr = EndpointAddress(address, transport, port)
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
        interface.host_scan(HostScan(evidence, address, host_services))

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        # only Internet-facing scan
        if isinstance(entity, IoTSystem):
            return [Properties.EXPECTED_HOSTS]
        if isinstance(entity, Host) and entity.is_global():
            return [Properties.EXPECTED_SERVICES]
        if isinstance(entity, Service) and entity.get_parent_host().is_global() and entity.protocol == Protocol.HTTP:
            return [Properties.HTTP_REDIRECT]
        return []


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
