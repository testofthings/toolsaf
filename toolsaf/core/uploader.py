"""JSON serialized statement uploader"""
from typing import Union, Literal, Dict, List, Any
from pathlib import Path
import requests
from toolsaf.main import ConfigurationException


class Uploader:
    """JSON serialized statement uploader"""

    _api_url = "https://127.0.0.1/api"

    def __init__(self, key_file_argument: Union[Literal[True], str],
                 statement_name: str) -> None:
        self._key_file_arg = key_file_argument
        self.statement_name = statement_name
        self.statement_name_url = self.statement_name.replace(" ", "-")
        self._api_key = ""

    def _get_key_file_path_based_on_argument(self) -> Path:
        """Get path to API key file based on user given command line argument"""
        if self._key_file_arg is True:
            return Path.home() / ".toolsaf/.apikey"
        return Path(self._key_file_arg)

    def read_api_key(self) -> None:
        """Read API key from file"""
        key_file_path = self._get_key_file_path_based_on_argument()
        if not Path.exists(key_file_path):
            raise ConfigurationException(f"API key file not found at {key_file_path}")
        with Path.open(key_file_path, "r", encoding="utf-8") as api_key_file:
            self._api_key = api_key_file.read().strip()

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
