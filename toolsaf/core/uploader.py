"""JSON serialized statement uploader"""
import os
import sys
from typing import Union, Literal, Dict, List, Any
from pathlib import Path
import requests
from toolsaf.main import ConfigurationException


class Uploader:
    """JSON serialized statement uploader"""

    _toolsaf_home_dir = Path.home() / ".toolsaf"
    _api_url = "https://127.0.0.1/api"

    def __init__(self, statement_name: str) -> None:
        self.statement_name = statement_name
        self.statement_name_url = self.statement_name.replace(" ", "-")
        self._api_key = ""

    def do_pre_procedures(self, key_file_argument: Union[Literal[True], str]) -> None:
        """Get everything ready for uploading"""
        self._add_toolsaf_directory_to_home()
        self._add_directory_for_current_statement()
        key_file_path = self._get_key_file_path_based_on_argument(key_file_argument)
        self._read_api_key(key_file_path)

    def _create_directory(self, path: Path) -> None:
        """Creates directory based on given Path; if the directory does not already exist"""
        if not path.exists():
            path.mkdir()

    def _add_toolsaf_directory_to_home(self) -> None:
        """Adds .toolsaf to user's home directory"""
        self._create_directory(self._toolsaf_home_dir)

    def _add_directory_for_current_statement(self) -> None:
        """Create a subdirectory for current statement in .toolsaf/"""
        called_from = sys.path[0].rsplit('/', maxsplit=1)[-1]
        self._create_directory(self._toolsaf_home_dir / called_from)

    def _get_key_file_path_based_on_argument(self, key_file_argument: Union[Literal[True], str]) -> Path:
        """Get path to API key file based on user given command line argument"""
        if key_file_argument is True:
            return self._toolsaf_home_dir / ".apikey"
        return Path(os.path.abspath(key_file_argument))

    def _read_api_key(self, key_file_path: Path) -> None:
        """Read API key from file"""
        print(f"Reading API key from {key_file_path}")
        if not Path.exists(key_file_path):
            raise ConfigurationException(f"API key file not found at {key_file_path}")
        with Path.open(key_file_path, "r", encoding="utf-8") as api_key_file:
            file_contents = api_key_file.read().strip()
            if not file_contents:
                raise ConfigurationException(f"API key file {key_file_path} is empty")
            self._api_key = file_contents

    @property
    def _headers(self) -> Dict[str, str]:
        """API request headers"""
        return {
            "Authorization": self._api_key,
            "Content-Type": "application/json"
        }

    def _post(self, url: str, data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> requests.Response:
        """POST given data to url"""
        try:
            # Remove verify=False
            return requests.post(url, json=data, headers=self._headers, verify=False, timeout=60)
        except ConnectionError as e:
            raise ConnectionError("Data upload failed!") from e

    def _handle_response(self, response: requests.Response) -> None:
        print(response.json())

    def upload_statement(self) -> None:
        """Upload statement info to API"""
        url = f"{self._api_url}/statement"
        response = self._post(url, {"name": self.statement_name, "url": self.statement_name_url})
        self._handle_response(response)

    def upload_system(self, entities: List[Dict[str, Any]]) -> None:
        """Upload entities to the API"""
        url = f"{self._api_url}/statement/{self.statement_name_url}/entities"
        response = self._post(url, entities)
        self._handle_response(response)

    def upload_logs(self, entries: List[Dict[str, Any]]) -> None:
        """Upload sources and events to the API"""
        url = f"{self._api_url}/statement/{self.statement_name_url}/logs"
        new_structure: List[Dict[str, Any]] = []
        current_entries = 0

        for entry in entries:
            if entry["type"] == "source":
                if current_entries >= 3000:
                    response = self._post(url, new_structure)
                    self._handle_response(response)
                    new_structure = []
                    current_entries = 0

                entry["events"] = []
                new_structure += [entry]
            else:
                new_structure[-1]["events"] += [entry]
            current_entries += 1

        if new_structure:
            response = self._post(url, new_structure)
            self._handle_response(response)
