"""JSON serialized statement uploader"""
import os
from typing import Union, Dict, List, Any, Optional, cast
from pathlib import Path
import requests
from toolsaf.main import ConfigurationException
from toolsaf.core.model import IoTSystem


class Uploader:
    """JSON serialized statement uploader"""

    _toolsaf_home_dir = Path.home() / ".toolsaf"

    def __init__(self, system: IoTSystem, allow_insecure: bool=False) -> None:
        self.statement_name = system.name
        self.statement_url = system.upload_tag
        if not self.statement_url:
            raise ConfigurationException("Tag missing. Use system.tag() in your statement")
        self.allow_insecure = allow_insecure
        self._api_key = ""
        self._api_url = ""
        self._key_file_path: Path

    def do_upload_pre_procedures(self, key_file_argument: Optional[str]) -> None:
        """Get everything ready for uploading"""
        self._add_toolsaf_directory_to_home()
        self._key_file_path = self._get_key_file_path_based_on_argument(key_file_argument)
        self._read_api_url()
        self._read_api_key()

    def _create_directory(self, path: Path) -> None:
        """Creates directory based on given Path; if the directory does not already exist"""
        if not path.exists():
            path.mkdir()

    def _add_toolsaf_directory_to_home(self) -> None:
        """Adds .toolsaf to user's home directory"""
        self._create_directory(self._toolsaf_home_dir)

    def _get_key_file_path_based_on_argument(self, key_file_argument: Optional[str]) -> Path:
        """Get path to API key file based on user given command line argument"""
        if key_file_argument is None:
            return self._toolsaf_home_dir / ".api_key"
        return Path(os.path.abspath(key_file_argument))

    def _read_api_url(self) -> None:
        """Read API URL from file, if not found, create it and prompt user to enter it"""
        url_file_path = self._toolsaf_home_dir / "api_url"
        if not Path.exists(url_file_path):
            print(f"Could not read API URL, file {url_file_path} not found")
            api_url = "https://"
            api_url += input(f"Enter URL for the API: {api_url}")
            with url_file_path.open("w", encoding="utf-8") as api_url_file:
                api_url_file.write(api_url)

        else:
            with url_file_path.open("r", encoding="utf-8") as api_url_file:
                api_url = api_url_file.read().strip()
                assert api_url, f"Could not read API URL, file {url_file_path} is empty"

        self._api_url = api_url

    def _read_api_key(self) -> None:
        """Read API key from file"""
        print(f"Reading API key from {self._key_file_path}")
        if not Path.exists(self._key_file_path):
            raise ConfigurationException(f"API key file not found at {self._key_file_path}")
        with Path.open(self._key_file_path, "r", encoding="utf-8") as api_key_file:
            file_contents = api_key_file.read().strip()
            if not file_contents:
                raise ConfigurationException(f"API key file {self._key_file_path} is empty")
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
            # Turn verification off if insecure connection are allowed
            verify = not self.allow_insecure
            return requests.post(url, json=data, headers=self._headers, verify=verify, timeout=60)
        except ConnectionError as e:
            raise ConnectionError("Data upload failed!") from e

    def _handle_response(self, response: requests.Response, stop_on_error: bool=False,
                         print_response_json: bool=True) -> Dict[str, Any]:
        """Handle response from server after data upload, returns response JSON"""
        response_json = cast(Optional[Dict[str, Any]], response.json())
        if not response_json:
            raise ConnectionError("Data upload failed! No JSON response from server")
        if stop_on_error and not response.ok:
            raise ConnectionError(f"Data upload failed! Server response was: {response_json.get('error')}")
        if print_response_json:
            print(response_json)
        return response_json

    def upload_statement(self) -> None:
        """Upload statement info to API"""
        url = f"{self._api_url}/api/statement"
        response = self._post(url, {"name": self.statement_name, "url": self.statement_url})
        self._handle_response(response)

    def upload_system(self, entities: List[Dict[str, Any]]) -> None:
        """Upload entities to the API"""
        url = f"{self._api_url}/api/statement/{self.statement_url}/entities"
        response = self._post(url, entities)
        self._handle_response(response, stop_on_error=True)

    def _upload_evidence_source(self, source: Dict[str, Any]) -> int:
        """Upload a single EvidenceSource to the API"""
        url = f"{self._api_url}/api/result/{self.statement_url}/evidence-source"
        response = self._post(url, source)
        response_json = self._handle_response(response, stop_on_error=True)
        if not (source_id := response_json.get("source_id")):
            raise ConnectionError("Data upload failed! No source_id returned from server")
        try:
            source_id = int(source_id)
        except ValueError as e:
            raise ConnectionError("Data upload failed! Invalid source_id returned from server") from e
        return source_id

    def _upload_events(self, events: List[Dict[str, Any]], source_id: int) -> None:
        """Upload Events related to an EvidenceSource"""
        url = f"{self._api_url}/api/result/evidence-source/{source_id}/events"
        response = self._post(url, events)
        self._handle_response(response, stop_on_error=True, print_response_json=False)

    def upload_logs(self, logs: List[Dict[str, Any]]) -> None:
        """Upload EvidenceSources and related Events in batches to the API"""
        events: List[Dict[str, Any]] = []
        source_id = 0
        for entry in logs:
            if entry["type"] == "source":
                if events:
                    self._upload_events(events, source_id)
                    events = []
                source_id = self._upload_evidence_source(entry)
            else:
                events.append(entry)
        if events:
            self._upload_events(events, source_id)

        # Everything uploaded
        response = self._post(f"{self._api_url}/api/result/{self.statement_url}/commit", {})
        self._handle_response(response, stop_on_error=False)


if __name__ == "__main__":
    test_system = IoTSystem()
    test_system.upload_tag = "test"
    u = Uploader(test_system)
    u.allow_insecure = True
