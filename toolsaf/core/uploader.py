"""JSON serialized statement uploader"""
import os
import http.server
import socketserver
import webbrowser
from typing import Union, Literal, Dict, List, Any
from pathlib import Path
import requests
from toolsaf.main import ConfigurationException

API_URL = "https://127.0.0.1"

class Uploader:
    """JSON serialized statement uploader"""

    _toolsaf_home_dir = Path.home() / ".toolsaf"
    _api_url = f"{API_URL}/api"

    def __init__(self, statement_name: str, allow_insecure: bool=False) -> None:
        self.statement_name = statement_name
        self.statement_name_url = self.statement_name.replace(" ", "-")
        self.allow_insecure = allow_insecure
        self._api_key = ""
        self._id_token = ""

    def do_pre_procedures(self, key_file_argument: Union[Literal[True], str]) -> None:
        """Get everything ready for uploading"""
        self._add_toolsaf_directory_to_home()
        key_file_path = self._get_key_file_path_based_on_argument(key_file_argument)
        self._read_api_key(key_file_path)

    def _create_directory(self, path: Path) -> None:
        """Creates directory based on given Path; if the directory does not already exist"""
        if not path.exists():
            path.mkdir()

    def _add_toolsaf_directory_to_home(self) -> None:
        """Adds .toolsaf to user's home directory"""
        self._create_directory(self._toolsaf_home_dir)

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
            # Turn verification off if insecure connection are allowed
            verify = not self.allow_insecure
            return requests.post(url, json=data, headers=self._headers, verify=verify, timeout=60)
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

    def upload_sources(self, sources: List[Dict[str, Any]]) -> None:
        """Upload EvidenceSources to the API"""
        url = f"{self._api_url}/statement/{self.statement_name_url}/evidence-sources"
        response = self._post(url, sources)
        self._handle_response(response)

    def upload_events(self, events: List[Dict[str, Any]]) -> None:
        """Upload Events in batches to the API"""
        url = f"{self._api_url}/statement/{self.statement_name_url}/events"
        for idx in range(0, len(events), 10000):
            response = self._post(url, events[idx:idx+10000])
            self._handle_response(response)

    def upload_logs(self, entries: List[Dict[str, Any]]) -> None:
        """Upload sources and events to the API"""
        sources, events = [], []
        for entry in entries:
            if entry["type"] == "source":
                sources.append(entry)
            else:
                events.append(entry)

        self.upload_sources(sources)
        self.upload_events(events)

    def _upload_logs(self, entries: List[Dict[str, Any]]) -> None:
        """Upload sources and events will probably replace this way"""
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


    def login(self) -> None:
        """Login using Google's OpenID Connect"""
        print(f"{API_URL}/login")
        response = requests.get(f"{API_URL}/login", verify=not self.allow_insecure, timeout=60) # Changeable url
        if response.status_code != 200:
            raise ConnectionError("Got incorrect response from login API")
        if not (response_json := response.json()):
            raise ConnectionError("Got incorrect response from login API")
        if not (auth_url := response_json.get("auth_url")):
            raise ConnectionError("Got incorrect response from login API")

        webbrowser.open(auth_url, autoraise=True)
        with self.CustomTCPServer(("localhost", 5033), self.TokenReceiver) as httpd:
            httpd.RequestHandlerClass.verify = not self.allow_insecure # type: ignore [attr-defined]
            httpd.handle_request()
            self._id_token = httpd.token
            httpd.server_close()

        if not self._id_token:
            raise ConnectionError("Getting a token failed")

        print(f"Your ID token is: {self._id_token}")

    class CustomTCPServer(socketserver.TCPServer):
        """Custom TCP Server"""
        token = ""
        allow_reuse_address = True

    class TokenReceiver(http.server.SimpleHTTPRequestHandler):
        """Token receiver"""
        verify = True

        def do_GET(self) -> None:
            if "/?code=" in self.path:
                resp = requests.get(f"{API_URL}/callback" + self.path[1:], verify=self.verify, timeout=60)

                if resp.status_code != 200:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    error_message = f"Error: {resp.json()['error']}. You can close the browser".encode('utf-8')
                    self.wfile.write(error_message)

                else:
                    self.server.token = resp.content # type: ignore [attr-defined]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Logged in, you can now close the browser")

        def log_message(self, format: str, *args: Any) -> None: # pylint: disable=W0622
            return

        def log_error(self, format: str, *args: Any) -> None: # pylint: disable=W0622
            return


if __name__ == "__main__":
    u = Uploader("test")
    u.allow_insecure = True
    u.login()
