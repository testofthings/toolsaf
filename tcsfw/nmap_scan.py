import datetime
from io import BytesIO
import pathlib
from typing import Dict, Set, List
from xml.etree import ElementTree

from tcsfw.address import IPAddress, HWAddress, EndpointAddress, Protocol
from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface
from tcsfw.model import IoTSystem, Host, Addressable
from tcsfw.property import PropertyKey, Properties
from tcsfw.tools import BaseFileCheckTool
from tcsfw.traffic import EvidenceSource, Evidence, ServiceScan, HostScan, Tool


class NMAPScan(BaseFileCheckTool):
    """Parse Nmap scan XML output"""
    def __init__(self, system: IoTSystem):
        super().__init__("nmap", system)
        self.tool.name = "Nmap scan"
        self.data_file_suffix = ".xml"

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        tree = ElementTree.parse(data)

        system = self.system

        run_stat = tree.getroot().find('runstats')
        finished_x = run_stat.find('finished')
        source.timestamp = datetime.datetime.fromtimestamp(int(finished_x.attrib.get('time')))
        evidence = Evidence(source)

        for host_x in tree.getroot().iter('host'):
            status_x = host_x.find('status')
            if status_x.get('state') != "up":
                continue

            ip_addr = None
            hw_addr = None
            for addr_x in host_x.iter('address'):
                raw_addr = addr_x.attrib.get('addr')
                addr_type = addr_x.attrib.get('addrtype')
                try:
                    if addr_type == 'ipv4':
                        ip_addr = IPAddress.new(raw_addr)
                    elif addr_type == 'mac':
                        hw_addr = HWAddress.new(raw_addr)
                    else:
                        self.logger.warning("Ignoring scanned address: %s", raw_addr)
                        continue
                except ValueError as e:
                    self.logger.exception(e)

            used_ads = system.get_addresses()
            if ip_addr in used_ads:
                host = system.get_endpoint(ip_addr)
                assert isinstance(host, Host)
            elif hw_addr in used_ads:
                host = system.get_endpoint(hw_addr)
                assert isinstance(host, Host)
                if ip_addr and not system.is_external(ip_addr):
                    system.learn_ip_address(host, ip_addr)
            else:
                # unknown addresses are not included to roster
                continue
            assert host is not None

            host_services = set()

            ports_x = host_x.find('ports')
            for port_x in ports_x.iter('port') or []:
                proto = Protocol[port_x.attrib.get('protocol').upper()]
                port = int(port_x.attrib.get('portid'))
                service_x = port_x.find("service")
                ad = EndpointAddress(ip_addr, proto, port)
                ad_name = service_x.attrib.get('name') if service_x is not None and 'name' in service_x.attrib else ""
                interface.service_scan(ServiceScan(evidence, ad, ad_name))
                host_services.add(ad)

            # summarize the seen ports
            interface.host_scan(HostScan(evidence, ip_addr or hw_addr, host_services))

        return True

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        if isinstance(entity, IoTSystem):
            return [Properties.EXPECTED_HOSTS]
        if isinstance(entity, Addressable) and not entity.is_global():
            return [Properties.EXPECTED_SERVICES]  # local hosts can be scanned
        return []
