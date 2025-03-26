"""Nmap scan result XML parser"""

from io import BufferedReader
from datetime import datetime
from typing import Set, Tuple, Optional
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from toolsaf.main import ConfigurationException
from toolsaf.common.address import IPAddress, HWAddress, EndpointAddress, Protocol, AnyAddress
from toolsaf.core.event_interface import EventInterface, PropertyAddressEvent
from toolsaf.core.model import IoTSystem
from toolsaf.adapters.tools import SystemWideTool
from toolsaf.common.traffic import EvidenceSource, Evidence, ServiceScan, HostScan
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict


class NMAPScan(SystemWideTool):
    """Parse Nmap scan XML output"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("nmap", system)
        self.tool.name = "Nmap scan"
        self.data_file_suffix = ".xml"
        self._host_services: Set[EndpointAddress] = set()

    def get_sub_element(self, element: Element, *names: str) -> Element:
        """Get sub element from element based on given element names"""
        for name in names:
            if not isinstance(sub_element := element.find(name), Element):
                raise ConfigurationException("Incorrect nmap .xml file formatting")
            element = sub_element
        return element

    def get_from_element(self, element: Element, value: str) -> str:
        """Get value from element"""
        if not isinstance((result := element.get(value)), str):
            raise ConfigurationException(f"Could not read value {value}")
        return result

    def get_timestamp(self, root: Element) -> datetime:
        """Get timestamp for nmap scan"""
        if (timestamp := self.get_sub_element(root, "runstats", "finished").get("time")) is None:
            raise ConfigurationException("Could not find timestamp fron nmap .xml")
        try:
            return datetime.fromtimestamp(int(timestamp))
        except ValueError as err:
            raise ConfigurationException(f"Could not convert {timestamp} to datetime") from err

    def host_state_is_up(self, host: Element) -> bool:
        """Check if host state is up"""
        return self.get_from_element(
            self.get_sub_element(host, "status"), "state"
        ) == "up"

    def get_addresses(self, host: Element) -> Tuple[Optional[IPAddress], Optional[HWAddress]]:
        """Get IP and or HW address from given xml element"""
        ip_addr, hw_addr = None, None
        for addr_info in host.iter("address"):
            raw_addr = self.get_from_element(addr_info, "addr")
            match self.get_from_element(addr_info, "addrtype"):
                case "ipv4":
                    ip_addr = IPAddress.new(raw_addr)
                case "mac":
                    hw_addr = HWAddress.new(raw_addr)
                case _:
                    self.logger.warning("Ignoring scanned address: %s", raw_addr)
        return ip_addr, hw_addr

    def get_port_info(self, port_info: Element) -> Tuple[Protocol, int, Optional[str]]:
        """Get protocol, port, and optional service name from port element"""
        protocol = Protocol.get_protocol(self.get_from_element(port_info, "protocol"))
        if protocol is None:
            raise ConfigurationException("Protocol not defined in Toolsaf")
        port = int(self.get_from_element(port_info, "portid"))
        service_name = None
        try:
            service = self.get_sub_element(port_info, "service")
            service_name = self.get_from_element(service, "name") if "name" in service.attrib else ""
        except ConfigurationException as _:
            pass
        return protocol, port, service_name

    def add_scans_to_address(self, address: AnyAddress, host: Element,
                          interface: EventInterface, evidence: Evidence) -> None:
        """Adds service and host scan results, based on xml element, to given address"""
        for port_info in self.get_sub_element(host, "ports").iter("port"):
            protocol, port, service_name = self.get_port_info(port_info)
            endpoint_addr = EndpointAddress(address, protocol, port)
            service_scan = ServiceScan(evidence, endpoint_addr, service_name or "")
            interface.service_scan(service_scan)
            self._host_services.add(endpoint_addr)

        scan = HostScan(evidence, address, self._host_services)
        interface.host_scan(scan)

        if not self._host_services:
            self.set_nothing_found(address, interface, evidence)

    def set_nothing_found(self, address: AnyAddress, interface: EventInterface,
                        evidence: Evidence) -> None:
        """Create property showing that no open ports were found but scan was run"""
        ev = PropertyAddressEvent(
            evidence, address,
            PropertyKey(self.tool_label, "ok").verdict(Verdict.PASS, "No open ports found")
        )
        interface.property_address_update(ev)

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        tree = ElementTree.parse(data)
        if not isinstance((root := tree.getroot()), Element):
            raise ConfigurationException("Incorrect nmap .xml file formatting")

        source.timestamp = self.get_timestamp(root)
        evidence = Evidence(source)

        for host in root.iter("host"):
            if not self.host_state_is_up(host):
                continue

            ip_addr, hw_addr = self.get_addresses(host)
            self._host_services = set()
            if isinstance(ip_addr, IPAddress):
                self.add_scans_to_address(ip_addr, host, interface, evidence)
            elif isinstance(hw_addr, HWAddress):
                self.add_scans_to_address(hw_addr, host, interface, evidence)

        return True
