"""JSON serialized statement uploader"""
from typing import Union, Literal, Iterable, Dict, Any
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

    def _post(self, url: str, data: Dict[str, Any]) -> requests.Response:
        """POST given data to url"""
        try:
            # Remove verify=False
            return requests.post(url, json=data, headers=self._headers, verify=False, timeout=60)
        except ConnectionError as e:
            raise ConnectionError("Data upload failed!") from e

    def upload_statement(self, statement_name: str) -> None:
        """Upload statement info to API"""
        url = f"{self._api_url}/statement"
        response = self._post(url, {"name": statement_name})
        response_json = response.json()
        print(response_json)

    def upload_system(self, system_stream: Iterable[Dict[str, Any]]) -> None:
        """Upload entities to the API"""
        for entry in system_stream:
            self._upload_entity(entry)

    def _upload_entity(self, entity: Dict[str, Any]) -> None:
        """Upload single entity to the API"""
        url = f"{self._api_url}/statement/{self.statement_name}/entity"
        response = self._post(url, entity)
        response_json = response.json()
        print(response_json)

    def _upload_evidence_source(self, source: Dict[str, Any]) -> None:
        """Upload single evidence source to the API"""
        url = f"{self._api_url}/statement/{self.statement_name}/evidence_source"
        response = self._post(url, source)
        response_json = response.json()
        print(response_json)

    def _upload_event(self, event: Dict[str, Any]) -> None:
        """Upload single event to the API"""
        url = f"{self._api_url}/statement/{self.statement_name}/source/{event['source-id']}/event"
        response = self._post(url, event)
        response_json = response.json()
        print(response_json)

    def upload_events(self, event: Dict[str, Any]) -> None:
        """Upload events to the API"""
        if event["type"] == "source":
            self._upload_evidence_source(event)
        elif event["type"] in ["service-scan", "host-scan"]:
            self._upload_event(event)
        else:
            # Unimplemented event types
            pass
