"""Shodan scan tool"""

import os
import json
import argparse
from io import BufferedReader
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any, Set, cast
from shodan.client import Shodan
from shodan.exception import APIError

from toolsaf.main import ConfigurationException
from toolsaf.adapters.tools import SystemWideTool
from toolsaf.core.model import IoTSystem, Service
from toolsaf.core.components import Software, SoftwareComponent
from toolsaf.core.event_interface import EventInterface, PropertyEvent
from toolsaf.common.traffic import EvidenceSource, Evidence, ServiceScan
from toolsaf.common.address import IPAddress, Protocol, EndpointAddress
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.common.verdict import Verdict


class ShodanScan(SystemWideTool):
    """Process Shodan scan results"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("shodan", system)
        self.tool.name = "Shodan tool"
        self.data_file_suffix = ".json"
        self._key_set: Set[PropertyKey]
        self._interface: EventInterface
        self._evidence: Evidence

    def determine_protocol(self, entry: Dict[str, Any]) -> Protocol:
        """Determine used protocol"""
        module: List[str] = entry["_shodan"]["module"].lower().split("-")
        if "https" in module:
            return Protocol.TLS
        for protocol in Protocol:
            if protocol.value in module:
                return protocol
        raise ConfigurationException(f"Could not determine protocol from Shodan module {module}")

    def get_open_port_info(self, entry: Dict[str, Any]) -> Tuple[int, Protocol, Protocol]:
        """Add open ports to endpoint"""
        port: int = entry["port"]
        transport = Protocol.get_protocol(entry["transport"])
        assert transport, "get_protocol returned None"
        protocol = self.determine_protocol(entry)
        return port, transport, protocol

    def add_http_status(self, protocol: Protocol, entry: Dict[str, Any], service: Service) -> None:
        """Add HTTP(S) status code to a HTTP(S) service's properties"""
        if protocol in [Protocol.HTTP, Protocol.TLS]:
            status_code = str(entry["http"]["status"])
            key_part = "http" if protocol == Protocol.HTTP else "https"
            key = PropertyKey(self.tool_label, key_part, "status", status_code)
            prop_event = PropertyEvent(self._evidence, service, key.verdict(Verdict.IGNORE))
            self._interface.property_update(prop_event)

    def add_vulnerabilities(self, vulnerabilities: Dict[str, Any], service: Service) -> None:
        """Add vulnerability to service's properties"""
        for vulnerability, info in vulnerabilities.items():
            if (key := PropertyKey(self.tool_label, vulnerability)) not in self._key_set:
                self._key_set.add(key)
                veridct = Verdict.FAIL
                comment = f"CVSS: {info['cvss']}, {info['summary']}"
                prop_event = PropertyEvent(self._evidence, service, key.verdict(veridct, comment))
                self._interface.property_update(prop_event)

    def add_heartbleed(self, opts_item: Dict[str, str], service: Service) -> None:
        """Add Heartbleed verdict to service's properties"""
        if "heartbleed" in opts_item and (key := PropertyKey(self.tool_label, "heartbleed")) not in self._key_set:
            self._key_set.add(key)
            comment = opts_item["heartbleed"].strip().split(" - ")[1]
            verdict = Verdict.PASS if comment.upper() == "SAFE" else Verdict.FAIL
            prop_event = PropertyEvent(self._evidence, service, key.verdict(verdict, comment))
            self._interface.property_update(prop_event)

    def parse_cpe23(self, cpe23: str) -> Tuple[str, Optional[str]]:
        """Extracts the product and version number (if included) from a given CPE 2.3 string.
            CPE 2.3 parts are cpe:2.3:<part>:<vendor>:<product>:<version>:...
        """
        components = cpe23.split(":")
        product = components[4]
        version = components[5] if len(components) > 5 and components[5] else None
        return product, version

    def add_cpes(self, cpe23_items: List[str], service: Service) -> None:
        """Add Common Platform Enumeration info to SW component and assign verdict based on statement SBOM"""
        parent = service.parent
        assert parent, f"{service} parent was None"
        if len(parent.components) > 0:
            parent_sw = cast(Software, parent.components[0])
            for entry in cpe23_items:
                product, version = self.parse_cpe23(entry)
                software = SoftwareComponent(product)
                verdict = Verdict.PASS if software in parent_sw.components.values() else Verdict.FAIL
                key = PropertyKey("component", product)
                comment = f"v{version}, Shodan CPE 2.3" if version else "Shodan CPE 2.3"
                self._interface.property_update(
                    PropertyEvent(self._evidence, parent_sw, key.verdict(verdict, comment))
                )

    def process_file(self, data: BufferedReader, file_name: str,
                     interface: EventInterface, source: EvidenceSource) -> bool:
        """Process file"""
        self._interface = interface
        self._evidence = Evidence(source)

        scan = cast(Dict[str, Any], json.load(data))
        ip_addr = IPAddress.new(file_name.split("-")[-1].replace(self.data_file_suffix, ""))

        entry: Dict[str, Any]
        for entry in scan.get("data", []):
            self._key_set = set()

            port, transport, protocol = self.get_open_port_info(entry)
            endpoint_addr = EndpointAddress(ip_addr, transport, port)
            service = interface.service_scan(
                ServiceScan(self._evidence, endpoint_addr, protocol.value)
            )
            assert service is not None, "Service is None"

            self.add_http_status(protocol, entry, service)
            self.add_vulnerabilities(entry.get("vulns", {}), service)
            self.add_heartbleed(entry.get("opts", {}), service)
            self.add_cpes(entry.get("cpe23", []), service)

            if self.send_events and self._key_set:
                prop_event = PropertyEvent(self._evidence, service, Properties.VULNERABILITIES.value_set(self._key_set))
                interface.property_update(prop_event)

        return True


class ShodanScanner:
    """Class for using Shodan API"""
    def __init__(self, api_key: Optional[str]) -> None:
        assert api_key, "Env variable SHODAN_API_KEY must be set"
        self.api = Shodan(api_key)
        self.base_dir: Path
        self.command: str
        self.addresses: List[str]

    def get_args(self) -> None:
        """Parse command line arguments"""
        arg_parser = argparse.ArgumentParser()
        arg_parser.add_argument("--base-dir", default="shodan", help="Base dir to create files into")
        arg_parser.add_argument("command", choices=["iplookup", "dnslookup", "credits"],
                                help="Command to use. iplookup = Host IP lookup, " +
                                "dnslookup = IP lookup based on DNS info, credits = Show remaining credits")
        arg_parser.add_argument("address", nargs="*", help="IP Address to scan using Shodan")
        args = arg_parser.parse_args()

        self.base_dir = Path(args.base_dir)
        self.command = args.command
        self.addresses = args.address

    def perform_command(self) -> None:
        """Perform action based on selected command"""
        match self.command:
            case "iplookup":
                self.ip_lookup()
            case "dnslookup":
                self.dns_lookup()
            case "credits":
                self.display_remaining_credits()
            case _:
                raise ConfigurationException(f"Unknown command {self.command}")

    def ip_lookup(self) -> None:
        """Perform host lookup on given IP addresses"""
        for address in self.addresses:
            self._get_info_on_ip(address, file_prefix="ip")

    def dns_lookup(self) -> None:
        """Perform DNS lookup on given domain names"""
        for domain in self.addresses:
            domain_info = cast(Dict[str, Any], self.api.dns.domain_info(domain))
            domain_file = self.base_dir / f"domain-{domain}.json"
            with domain_file.open("w") as file_obj:
                json.dump(domain_info, file_obj, indent=4)

            record: Dict[str, Any]
            for record in domain_info.get("data", []):
                if record["type"] == "A" and (ip:=record.get("value", "")):
                    # Record type is Address and IP included in data
                    self._get_info_on_ip(ip, file_prefix="dns")

    def _get_info_on_ip(self, ip: str, file_prefix: str="") -> None:
        """Fetch information on given IP address and save to JSON"""
        file = self.base_dir / f"{file_prefix}-{ip}.json"
        try:
            info = self.api.host(ip)
            with file.open("w") as file_obj:
                json.dump(info, file_obj, indent=4)
        except APIError as err:
            print(f"{ip}: Error: {err}")

    def display_remaining_credits(self) -> None:
        """Display Shodan remaining credits"""
        credit_info = self.api.info()
        print("Shodan credits left:")
        print(json.dumps(credit_info, indent=4))


if __name__ == '__main__':
    scanner = ShodanScanner(os.getenv('SHODAN_API_KEY'))
    scanner.get_args()
    scanner.perform_command()
