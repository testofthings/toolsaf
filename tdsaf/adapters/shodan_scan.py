"""Shodan scan tool"""

import os
import json
import argparse
from pathlib import Path
from typing import List, Dict, Union, Any, cast
from shodan.client import Shodan
from shodan.exception import APIError

from tdsaf.main import ConfigurationException


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
