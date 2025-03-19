"""JSON serialized statement uploader"""
import os
import http.server
import socketserver
import webbrowser
from typing import Union, Literal, Dict, List, Any
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
        self._jwt = ""

    def do_pre_procedures(self, key_file_argument: Union[Literal[True], str]) -> None:
        """Get everything ready for uploading"""
        self._add_toolsaf_directory_to_home()
        key_file_path = self._get_key_file_path_based_on_argument(key_file_argument)
        self._read_api_key(key_file_path)
        self._read_api_url()

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
                api_url = api_url_file.read()
                assert api_url, f"Could not read API URL, file {url_file_path} is empty"

        self._api_url = api_url

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

    def _get_session_jwt(self, url: str) -> str:
        """Get session JWT"""
        response = self._post(url, data={"port": self._use_port})
        if response.status_code != 200 \
         or not (response_json := response.json()) \
         or not (oauth_url := response_json.get("oauth_url")):
            raise ConnectionError("Got incorrect response from user registration API")
        webbrowser.open(oauth_url, autoraise=True)

        session_jwt = ""
        # Start TCP serve to catch response from OAth provider
        with self.CustomTCPServer(("localhost", self._use_port), self.JWTReceiver) as httpd:
            httpd.api_url = self._api_url
            httpd.verify = not self.allow_insecure
            httpd.use_port = self._use_port
            httpd.handle_request()
            session_jwt = httpd.received_jwt
            httpd.server_close()

        if not session_jwt:
            raise ConnectionError("Getting a session JWT failed")
        return session_jwt

    def _read_session_jwt(self) -> None:
        """Read session JWT from file"""
        jwt_file_path = self._toolsaf_home_dir / ".jwt"
        if not jwt_file_path.exists():
            raise ConfigurationException(f"{jwt_file_path} was not found")
        with jwt_file_path.open("r") as jwt_file:
            self._jwt = jwt_file.read().strip()

    def _write_session_jwt_to_file(self, session_jwt: str) -> None:
        """Write received session JWT to file"""
        print(f"Saving session JWT to {self._toolsaf_home_dir / '.jwt'}")
        with (self._toolsaf_home_dir / ".jwt").open("w") as jwt_file:
            jwt_file.write(session_jwt)

    def register(self) -> None:
        """Register to Test of Things cloud service. Currently not available for the public"""
        registration_url = f"{self._api_url}/api/google-register"
        self._jwt = self._get_session_jwt(registration_url)
        self._write_session_jwt_to_file(self._jwt)

    def login(self) -> None:
        """Login using Google's OpenID Connect"""
        login_url = f"{self._api_url}/api/google-login"
        self._jwt = self._get_session_jwt(login_url)
        self._write_session_jwt_to_file(self._jwt)

    def test_jwt(self) -> None:
        """Test that JWT is correct"""
        self._read_session_jwt()
        resp = requests.post(
            f"{self._api_url}/api/jwt-test", headers={"Authorization": f"Bearer {self._jwt}"},
            verify=not self.allow_insecure,
            timeout=60)
        print(resp.status_code)
        print(resp.json())

    class CustomTCPServer(socketserver.TCPServer):
        """Custom TCP Server"""
        api_url = ""
        use_port = 0
        received_jwt = ""
        verify = True
        allow_reuse_address = True

    class JWTReceiver(http.server.SimpleHTTPRequestHandler):
        """JWT receiver"""
        server: 'Uploader.CustomTCPServer'

        def do_GET(self) -> None:
            if "/?code=" in self.path:
                callback_url = \
                    f"{self.server.api_url}/api/google-callback" + self.path[1:] + f"&port={self.server.use_port}"
                resp = requests.get(callback_url, verify=self.server.verify, timeout=60)

                self.send_response(resp.status_code)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                response_json = resp.json()

                if resp.status_code != 200:
                    error = response_json.get("error")
                    message = f"<b>Error: {error}<br>You can close the browser.</b>".encode('utf-8')
                else:
                    self.server.received_jwt = response_json.get("jwt")
                    api_message = response_json.get("message")
                    message = f"<b>Logged in. {api_message}<br>You can now close the browser.</b>".encode("utf-8")

                self.wfile.write(message)

        def log_message(self, format: str, *args: Any) -> None: # pylint: disable=W0622
            return

        def log_error(self, format: str, *args: Any) -> None: # pylint: disable=W0622
            return


if __name__ == "__main__":
    test_system = IoTSystem()
    test_system.upload_tag = "test"
    u = Uploader(test_system)
    u.do_pre_procedures(True)
    u.allow_insecure = True
    u.login()
    u.test_jwt()
