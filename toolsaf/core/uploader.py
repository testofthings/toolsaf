"""JSON serialized statement uploader"""
import os
import http.server
import socketserver
import webbrowser
from typing import Union, Dict, List, Any, Optional
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
        self._use_port = 5033
        self._key_file_path: Path

    def _common_pre_procedures(self, key_file_argument: Optional[str]) -> None:
        """Common pre procedures for registration and uploading"""
        self._add_toolsaf_directory_to_home()
        self._key_file_path = self._get_key_file_path_based_on_argument(key_file_argument)
        self._read_api_url()

    def do_register_pre_procedures(self, key_file_argument: Optional[str]) -> None:
        """Get everything ready for registering a new user"""
        self._common_pre_procedures(key_file_argument)

    def do_upload_pre_procedures(self, key_file_argument: Optional[str]) -> None:
        """Get everything ready for uploading"""
        self._common_pre_procedures(key_file_argument)
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
            print(f"Could not read API URL, file {url_file_path} is empty")
            api_url = "https://"
            api_url += input(f"Enter URL for the API, {api_url}")
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

    def _handle_response(self, response: requests.Response) -> None:
        print(response.json())

    def upload_statement(self) -> None:
        """Upload statement info to API"""
        url = f"{self._api_url}/api/statement"
        response = self._post(url, {"name": self.statement_name, "url": self.statement_url})
        self._handle_response(response)

    def upload_system(self, entities: List[Dict[str, Any]]) -> None:
        """Upload entities to the API"""
        url = f"{self._api_url}/api/statement/{self.statement_url}/entities"
        response = self._post(url, entities)
        self._handle_response(response)

    def upload_logs(self, logs: List[Dict[str, Any]]) -> None:
        """Upload EvidenceSources and related Events in batches to the API"""
        url = f"{self._api_url}/api/statement/{self.statement_url}/events"
        batch: List[Dict[str, Any]] = []
        for entry in logs:
            if entry["type"] == "source" and batch and batch[0] != entry:
                self._upload_batch(batch, url)
                batch = []
            batch.append(entry)

        if batch:
            self._upload_batch(batch, url)

    def _upload_batch(self, batch: List[Dict[str, Any]], url: str) -> None:
        """Post a single batch containing one EvidenceSource and its Events"""
        print(f"Uploading {batch[0]['base_ref']}")
        response = self._post(url, batch)
        self._handle_response(response)

    def _register_and_get_api_key(self, url: str) -> str:
        """Register Toolsaf user and get an API key for a successful registration"""
        response = self._post(url, data={"port": self._use_port})
        if response.status_code != 200 \
         or not (response_json := response.json()) \
         or not (oauth_url := response_json.get("oauth_url")):
            raise ConnectionError("Got incorrect response from user registration API")
        webbrowser.open(oauth_url, autoraise=True)

        callback_service = "github" if "github" in url else "google"

        api_key: Optional[str] = None
        # Start TCP serve to catch response from the OAth provider
        with self.CustomTCPServer(("localhost", self._use_port), self.APIKeyReceiver) as httpd:
            httpd.api_url = self._api_url
            httpd.callback_service = callback_service
            httpd.verify = not self.allow_insecure
            httpd.use_port = self._use_port
            httpd.handle_request()
            api_key = httpd.received_api_key
            httpd.server_close()

        if not api_key:
            raise ConnectionError("Getting an API key failed")
        return api_key

    def _write_api_key_to_file(self, api_key: str) -> None:
        """Write received API key to file"""
        print(f"Writing your API key to {self._key_file_path}")

        if not self._key_file_path.parents[0].exists():
            os.makedirs(self._key_file_path.parents[0], exist_ok=True)
        with open(self._key_file_path, "w", encoding="utf-8") as api_key_file:
            api_key_file.write(api_key)

    def _register(self, registration_url: str) -> None:
        """Common registration functionalities"""
        self._api_key = self._register_and_get_api_key(registration_url)
        self._write_api_key_to_file(self._api_key)

    def google_register(self) -> None:
        """Register to Test of Things cloud service using Google OAuth. Currently not available for the public"""
        registration_url = f"{self._api_url}/api/google-register"
        self._register(registration_url)

    def github_register(self) -> None:
        """Register to Test of Things cloud service using GitHub OAuth. Currently not available for the public"""
        registration_url = f"{self._api_url}/api/github-register"
        self._register(registration_url)

    class CustomTCPServer(socketserver.TCPServer):
        """Custom TCP Server"""
        api_url = ""
        callback_service = ""
        use_port = 0
        received_api_key = ""
        verify = True
        allow_reuse_address = True

    class APIKeyReceiver(http.server.SimpleHTTPRequestHandler):
        """API key receiver"""
        server: 'Uploader.CustomTCPServer'

        def do_GET(self) -> None:
            if "/?code=" in self.path:
                callback_url = \
                    f"{self.server.api_url}/api/{self.server.callback_service}-callback" \
                        + self.path[1:] + f"&port={self.server.use_port}"
                resp = requests.get(callback_url, verify=self.server.verify, timeout=60)

                # Read received API key from response headers
                self.server.received_api_key = resp.headers.get("Authorization")

                # Display response to user in the browser
                self.send_response(resp.status_code)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                message = resp.content
                self.wfile.write(message)

        def log_message(self, format: str, *args: Any) -> None: # pylint: disable=W0622
            return

        def log_error(self, format: str, *args: Any) -> None: # pylint: disable=W0622
            return


if __name__ == "__main__":
    test_system = IoTSystem()
    test_system.upload_tag = "test"
    u = Uploader(test_system)
    u.do_register_pre_procedures(None)
    u.allow_insecure = True
    #u.google_register()
    u.github_register()
