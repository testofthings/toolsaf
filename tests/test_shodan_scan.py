import os
import json
import pytest
import argparse
from shodan import Shodan
from pathlib import Path
from unittest.mock import MagicMock, patch

from tdsaf.adapters.shodan_scan import ShodanScanner
from tdsaf.main import ConfigurationException

ARGS = [
    ("scan", "scan"),
    ("iplookup", "ip_lookup"),
    ("dnslookup", "dns_lookup"),
    ("credits", "display_remaining_credits"),
    ("unknown", None)
]


def test_get_api_key():
    with patch("os.getenv", return_value=""):
        with pytest.raises(AssertionError):
            ShodanScanner(api_key=os.getenv("SHODAN_API_KEY"))

    with patch("os.getenv", return_value="test"):
        scanner = ShodanScanner(api_key=os.getenv("SHODAN_API_KEY"))
        assert scanner.api.api_key == "test"


@pytest.mark.parametrize(
    "argv, exp",
    [
        (["", ARGS[0][0]], (Path("shodan"), ARGS[0][0], [])),
        (["", ARGS[1][0]], (Path("shodan"), ARGS[1][0], [])),
        (["", ARGS[2][0]], (Path("shodan"), ARGS[2][0], [])),
        (["", ARGS[3][0], "ip1", "ip2"], (Path("shodan"), ARGS[3][0], ["ip1", "ip2"])),
        (["", "--base-dir", "test", ARGS[0][0], "ip1", "ip2"], (Path("test"), ARGS[0][0], ["ip1", "ip2"])),
    ])
def test_get_args(argv, exp):
    scanner = ShodanScanner("api_key")
    with patch("argparse._sys.argv", argv):
        scanner.get_args()
        assert scanner.base_dir == exp[0]
        assert scanner.command == exp[1]
        assert scanner.addresses == exp[2]


def test_perform_command():
    scanner = ShodanScanner("api_key")
    scanner.scan = MagicMock()
    scanner.ip_lookup = MagicMock()
    scanner.dns_lookup = MagicMock()
    scanner.display_remaining_credits = MagicMock()

    for cmd, method in ARGS:
        scanner.command = cmd
        if method:
            scanner.perform_command()
            getattr(scanner, method).assert_called_once()
        else:
            with pytest.raises(ConfigurationException):
                scanner.perform_command()


def test_display_remaining_credits():
    scanner = ShodanScanner("api_key")
    scanner.api.info = MagicMock(return_value={"credits": 100})
    with patch("builtins.print") as mock_print:
        scanner.display_remaining_credits()
        mock_print.assert_called_with(json.dumps({"credits": 100}, indent=4))
