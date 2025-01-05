"""Shodan scan tool"""

import os
import json
import argparse
from io import BufferedReader
from pathlib import Path
from typing import List, Dict, Union, Any, Set, cast
from shodan.client import Shodan
from shodan.exception import APIError

from tdsaf.adapters.tools import SystemWideTool
from tdsaf.core.model import IoTSystem, Service
from tdsaf.core.event_interface import EventInterface, PropertyEvent
from tdsaf.common.traffic import EvidenceSource, Evidence, ServiceScan
from tdsaf.main import ConfigurationException
from tdsaf.common.address import IPAddress, Protocol, EndpointAddress
from tdsaf.common.property import Properties, PropertyKey
from tdsaf.common.verdict import Verdict


class ShodanScan(SystemWideTool):
    """Process Shodan scan results"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("shodan", system)
        self.tool.name = "Shodan tool"
        self.data_file_suffix = ".json"

    def determine_protocol(self, entry: Dict[str, Any]) -> Protocol:
        """Determine used protocol"""
        if "ssl" in entry or "tls" in entry:
            return Protocol.TLS
        if "http" in entry:
            return Protocol.HTTP
        if (protocol := Protocol.get_protocol(entry["product"])) is None:
            raise ConfigurationException(f"Protocol {entry['product']} not defined")
        return protocol

    def process_file(self, data: BufferedReader, file_name: str,
                     interface: EventInterface, source: EvidenceSource) -> bool:
        """Process file"""
        evidence = Evidence(source)

        scan = cast(Dict[str, Any], json.load(data))
        ip_addr = IPAddress.new(file_name.split("-")[-1].replace(self.data_file_suffix, ""))

        entry: Dict[str, Any]
        for entry in scan.get("data", []):
            # Open ports
            port: int = entry["port"]
            protocol = self.determine_protocol(entry)
            transport = cast(Protocol, Protocol.get_protocol(entry["transport"]))

            endpoint_addr = EndpointAddress(ip_addr, transport, port)
            service_scan = ServiceScan(evidence, endpoint_addr, protocol.value)
            a: Service = interface.service_scan(service_scan)

            # Vulnerabilities
            key_set: Set[PropertyKey] = set()
            for vulnerability in entry.get("vulns", {}):
                if (key := PropertyKey(self.tool_label, vulnerability)) not in key_set:
                    key_set.add(key)
                    veridct = Verdict.FAIL
                    ev = PropertyEvent(evidence, a, key.verdict(veridct))
                    interface.property_update(ev)

            if self.send_events:
                ev = PropertyEvent(evidence, a, Properties.VULNERABILITIES.value_set(key_set))
                interface.property_update(ev)

        return True


class ShodanScanner:
    """Class for using Shodan API"""
    def __init__(self, api_key: Union[str, None]) -> None:
        assert api_key, "Env variable SHODAN_API_KEY must be set"
        self.api = Shodan(api_key)
        self.base_dir: Path
        self.command: str
        self.addresses: List[str]

    def get_args(self) -> None:
        """Parse command line arguments"""
        arg_parser = argparse.ArgumentParser()
        arg_parser.add_argument("--base-dir", default="shodan", help="Base dir to create files into")
        arg_parser.add_argument("command", choices=["scan", "iplookup", "dnslookup", "credits"],
                                help="Command to use. scan = On-demand scan, iplookup = Host IP lookup, " +
                                "dnslookup = IP lookup based on DNS info, credits = Show remaining credits")
        arg_parser.add_argument("address", nargs="*", help="IP Address to scan using Shodan")
        args = arg_parser.parse_args()

        self.base_dir = Path(args.base_dir)
        self.command = args.command
        self.addresses = args.address

    def perform_command(self) -> None:
        """Perform action based on selected command"""
        match self.command:
            case "scan":
                self.scan()
            case "iplookup":
                self.ip_lookup()
            case "dnslookup":
                self.dns_lookup()
            case "credits":
                self.display_remaining_credits()
            case _:
                raise ConfigurationException(f"Unknown command {self.command}")

    def scan(self) -> None:
        # A scan done with the API will not give you this info
        # "No open ports found or the host has been recently crawled and cant get scanned again so soon."
        """Request on-demand scan for given IP addresses
        if len(self.addresses) == 0:
            scan_reqs = glob.glob("./" + self.base_dir.as_posix() + "/scan-req-*.json")
            for req in scan_reqs:
                with open(req, "r") as f:
                    id = json.load(f)["id"]
                    if self.api.scan_status(id)["status"] == "DONE":
                        print(f"Scan ID {id} is done")
                        file_id = req.split("scan-req-")[-1]

                        with (self.base_dir / f"scan-{'file_id'}").open("w") as f:
                            for banner in self.api.search_cursor(f"scan:{id}"):
                                json.dump(banner, f, indent=4, sort_keys=True)

        for address in self.addresses:
            print(f"Requesting On-Demand scan for {address}")
            info = self.api.scan(address, True)
            file = self.base_dir / f"scan-req-{address}.json"

            with file.open("w") as f:
                json.dump(info, f, indent=4)
        """

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
                json.dump(domain_info, file_obj, indent=4, sort_keys=True)

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
                json.dump(info, file_obj, indent=4, sort_keys=True)
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
