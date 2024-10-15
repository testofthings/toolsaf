"""Clinet tool for TCSFW"""

import argparse
from getpass import getpass
import json
import logging
import pathlib
import shutil
import sys
import time
from typing import BinaryIO, Dict, List
import tempfile
from urllib.parse import urlparse, urlunparse
import zipfile

import requests
import urllib3

from tcsfw.batch_import import FileMetaInfo
from tcsfw.command_basics import API_KEY_FILE_NAME, get_api_key

class ClientTool:
    """Client tool"""
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.auth_token = get_api_key()
        self.timeout = -1
        self.secure = True
        self.force_upload = False
        self.dry_run = False

    def run(self):
        """Run the client tool"""
        parser = argparse.ArgumentParser(prog="tcsfw", description="TCSFW client tool")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)
        parser.add_argument("--timeout", type=int, default=300, help="Server timeout, default is 5 min")
        parser.add_argument("--insecure", action="store_true", help="Allow insecure server connections")

        subparsers = parser.add_subparsers(title="commands", dest="command")
        subparsers.required = True

        # Subcommand: get api key
        key_parser = subparsers.add_parser("get-key", help="Get API key")
        key_parser.add_argument("--url", "-u", help="Server URL")
        key_parser.add_argument("--name", "-n", help="User name (leave out for prompt)")
        key_parser.add_argument("--password", "-p", help="User password (leave out for prompt)")
        key_parser.add_argument("--save", "-s", action="store_true",
                                help=f"Save API key to {API_KEY_FILE_NAME} (default is to stdout)")

        # Subcommand: upload files
        upload_parser = subparsers.add_parser("upload", help="Upload tool output")
        upload_parser.add_argument("--read", "-r", help="Path to file or directory to upload, default stdin")
        upload_parser.add_argument("--meta", "-m", help="Meta-data in JSON format")
        upload_parser.add_argument("--url", "-u", default="", help="Server URL")
        upload_parser.add_argument("--api-key", help="API key for server (avoid providing by command line)")
        upload_parser.add_argument("--force-upload", "-f", action="store_true", help="Force upload for all files")
        upload_parser.add_argument("--dry-run", action="store_true", help="Only print files to be uploaded")

        # Subcommand: reload statement
        reload_parser = subparsers.add_parser("reload", help="Reset statement")
        reload_parser.add_argument("--url", "-u", help="Server URL")
        reload_parser.add_argument("--api-key", help="API key for server (avoid providing by command line)")
        reload_parser.add_argument("--param", help="Specify reload parameters by JSON")

        # Subcommand: views
        show_parser = subparsers.add_parser("show", help="Show view")
        show_parser.add_argument("view", help="Name of the view")
        show_parser.add_argument("--url", "-u", help="Server URL")
        show_parser.add_argument("--api-key", help="API key for server (avoid providing by command line)")

        args = parser.parse_args()
        logging.basicConfig(format='%(message)s', level=getattr(
            logging, args.log_level or 'INFO'))

        self.timeout = args.timeout
        self.secure = not args.insecure

        if args.command == "get-key":
            self.run_get_key(args)
        elif args.command == "reload":
            self.run_reload(args)
        elif args.command == "show":
            self.run_show(args)
        else:
            self.run_upload(args)

    def run_get_key(self, args: argparse.Namespace):
        """Run get-key subcommand"""
        url = args.url.strip()
        if not url:
            raise ValueError("Missing server URL")
        save = args.save
        user_name = args.name
        user_password = args.password
        if not user_name:
            user_name = input("Username: ")
        if user_password is None:
            user_password = getpass("Password: ")
        u = urlparse(url)
        base_url = f"{u.scheme}://{u.netloc}"
        path = urlunparse(('', '', u.path, u.params, u.query, u.fragment))

        login_url = f"{base_url}/login/{path}"
        self.logger.info("Getting API key from %s", login_url)
        headers = {"X-User": user_name}  # Only in development, when missing authenticator from between
        resp = requests.get(login_url, timeout=self.timeout, auth=(user_name, user_password), headers=headers,
                            verify=self.secure)
        resp.raise_for_status()

        resp_json = resp.json()
        api_key = resp_json.get("api_key")
        if save:
            with pathlib.Path(API_KEY_FILE_NAME).open("w", encoding="utf-8") as f:
                f.write(f"{api_key}\n")
            self.logger.info("API key saved to %s", API_KEY_FILE_NAME)
        else:
            print(f"{api_key}")

    def run_reload(self, args: argparse.Namespace):
        """Run reload subcommand"""
        url = args.url.strip()
        if not url:
            raise ValueError("Missing server URL")
        u = urlparse(url)
        path = urlunparse(('', '', u.path, u.params, u.query, u.fragment))

        api_url = self.resolve_api_url(url)
        use_url = f"{api_url}/reload{path}"

        params = json.loads(args.param) if args.param else {}

        self.auth_token = args.api_key or self.auth_token
        if not self.auth_token:
            raise ValueError("Missing API key")
        if not self.secure:
            self.logger.warning("Disabling TLS verification for server connection")
            urllib3.disable_warnings()
        self.logger.info("Reset %s...", use_url)
        headers = {
            "Content-Type": "application/json",
            "X-Authorization": self.auth_token,
        }
        resp = requests.post(use_url, headers=headers, json=params,
                             timeout=self.timeout, verify=self.secure)
        resp.raise_for_status()
        self.logger.info("statement reload")

    def run_upload(self, args: argparse.Namespace):
        """Run upload subcommand"""
        meta_json = json.loads(args.meta) if args.meta else {}
        self.dry_run = args.dry_run or False
        url = args.url.strip()
        if not url:
            raise ValueError("Missing server URL")

        self.force_upload = args.force_upload or False
        if self.dry_run:
            self.logger.warning("DRY RUN, no files will be uploaded")
        self.auth_token = args.api_key or self.auth_token
        if not self.secure:
            self.logger.warning("Disabling TLS verification for server connection")
            urllib3.disable_warnings()
        if args.read:
            read_file = pathlib.Path(args.read)
            if read_file.is_dir():
                # uploading data from directory with meta-files in place
                self.upload_directory(url, read_file)
            else:
                # uploading single file
                if not meta_json:
                    raise ValueError("Missing upload meta-data")
                self.logger.info("Uploading %s to %s...", read_file.as_posix(), url)
                with read_file.open('rb') as f:
                    self.upload_file(url, f, meta_json)

        else:
            # uploading from stdin
            if not meta_json:
                raise ValueError("Missing upload meta-data")
            if "from_pipe" not in meta_json:
                meta_json["from_pipe"] = True  # tell server that file name carries no meaning
            self.logger.info("Uploading to %s...", url)
            self.upload_file(url, sys.stdin.buffer, meta_json)
        self.logger.info("upload complete")

    def upload_file(self, url: str, file_data: BinaryIO, meta_json: Dict):
        """Upload a file"""
        # create a temporary zip file
        if self.dry_run:
            return
        with tempfile.NamedTemporaryFile(suffix='.zip') as temp_file:
            self.create_zipfile(file_data, meta_json, temp_file)
            self.upload_file_data(url, temp_file)

    def upload_directory(self, url: str, path: pathlib.Path):
        """Upload directory"""
        files = sorted(path.iterdir(), key=lambda f: (f.is_dir(), f.name))  # files first

        meta_file = path / "00meta.json"
        if meta_file.exists():
            with meta_file.open() as f:
                meta_json = json.load(f)
            file_load_order = meta_json.get("file_order", [])
            if file_load_order:
                # sort files by file_load_order
                files = FileMetaInfo.sort_load_order(files, file_load_order)
        else:
            meta_json = None  # not {}

        # files to upload
        to_upload = self.filter_data_files(files)

        if meta_json is not None and to_upload:
            to_upload.insert(0, meta_file)  # upload also meta file, make it first
            self.logger.info("%s", meta_file.as_posix())

            # meta file exists -> upload files from here
            self.logger.info("%s/", path.as_posix())
            with tempfile.NamedTemporaryFile(suffix='.zip') as temp_file:
                self.copy_to_zipfile(to_upload, temp_file)
                self.upload_file_data(url, temp_file)

            # mark files as uploaded
            if not self.dry_run:
                for f in to_upload:
                    if f != meta_file:
                        self.mark_uploaded(f)

        # visit subdirectories
        for subdir in files:
            if subdir.is_dir():
                self.upload_directory(url, subdir)

    def create_zipfile(self, file_data: BinaryIO, meta_json: Dict, temp_file: BinaryIO):
        """Create zip file"""
        chunk_size = 256 * 1024
        with zipfile.ZipFile(temp_file.name, 'w') as zip_file:
            # write meta-data
            zip_file.writestr("00meta.json", json.dumps(meta_json))
            # write content
            zip_info = zipfile.ZipInfo("data")
            with zip_file.open(zip_info, "w") as of:
                chunk = file_data.read(chunk_size)
                while chunk:
                    of.write(chunk)
                    chunk = file_data.read(chunk_size)
        temp_file.seek(0)

    def copy_to_zipfile(self, files: List[pathlib.Path], temp_file: BinaryIO) -> bool:
        """Copy files from directory into zipfile"""
        chunk_size = 256 * 1024
        with zipfile.ZipFile(temp_file.name, 'w') as zip_file:
            for file in files:
                if not file.is_file():
                    continue
                # skip too large files
                file_size_mb = file.stat().st_size // (1024 * 1024)
                if file_size_mb > 1024:
                    self.logger.warning("File too large: %s (%d > 1024 M)", file.as_posix(), file_size_mb)
                    continue
                # write content
                self.logger.info("%s", file.as_posix())
                zip_info = zipfile.ZipInfo(file.name)
                with file.open("rb") as file_data:
                    with zip_file.open(zip_info, "w") as of:
                        chunk = file_data.read(chunk_size)
                        while chunk:
                            of.write(chunk)
                            chunk = file_data.read(chunk_size)
        temp_file.seek(0)

    def upload_file_data(self, url: str, temp_file: BinaryIO):
        """Upload content zip file into the server"""
        if self.dry_run:
            return
        api_url = self.resolve_api_url(url)
        upload_url = f"{api_url}/batch"
        headers = {
            "Content-Type": "application/zip",
        }
        if self.auth_token:
            headers["X-Authorization"] = self.auth_token
        multipart = {"file": temp_file}
        resp = requests.post(upload_url, files=multipart, headers=headers, timeout=self.timeout, verify=self.secure)
        resp.raise_for_status()

    def run_show(self, args: argparse.Namespace):
        """Textual views"""
        view = args.view
        url = args.url.strip()
        if not url:
            raise ValueError("Missing server URL")
        api_url = self.resolve_api_url(url)
        table_url = f"{api_url}/table/{view}"
        headers = {}
        if self.auth_token:
            headers["X-Authorization"] = self.auth_token

        while True:
            wid, hei = shutil.get_terminal_size()
            use_url = f"{table_url}?screen={wid}x{hei}"
            resp = requests.get(use_url, timeout=self.timeout, headers=headers, verify=self.secure)
            resp.raise_for_status()
            print('\033[2J\033[H', end='')  # clear screen and move cursor to top
            print(resp.text)
            time.sleep(1)

    def resolve_api_url(self, url: str) -> str:
        """Query server for API URL"""
        # split URL into host and statement
        if url.endswith("/"):
            raise ValueError("URL should not end with /")
        u = urlparse(url)
        base_url = f"{u.scheme}://{u.netloc}"
        path = urlunparse(('', '', u.path, u.params, u.query, u.fragment))
        # first query to resolve right server address
        query_url = f"{base_url}/api1/proxy{path}"
        headers = {
            "Content-Type": "application/json",
        }
        if self.auth_token:
            headers["X-Authorization"] = self.auth_token
        else:
            self.logger.warning("No API key found for upload")
        resp = requests.get(query_url, headers=headers, timeout=self.timeout, verify=self.secure)
        resp.raise_for_status()
        api_proxy = resp.json().get("api_proxy")
        return f"{base_url}/api1" if not api_proxy else f"{base_url}/proxy/{api_proxy}/api1"

    def filter_data_files(self, files: List[pathlib.Path]) -> List[pathlib.Path]:
        """Filter data files"""
        r = []
        for f in files:
            if not f.is_file() or f.name == "00meta.json":
                continue
            if f.suffix.lower() in {".meta", ".bak", ".tmp", ".temp"}:
                continue
            if f.name.startswith(".") or f.name.endswith("~"):
                continue
            if not self.force_upload and self.is_uploaded(f):
                continue
            r.append(f)
        return r

    @classmethod
    def is_uploaded(cls, path: pathlib.Path) -> bool:
        """Check if file has been uploaded"""
        p = path.parent / f".{path.name}.up"
        return p.exists()

    @classmethod
    def mark_uploaded(cls, path: pathlib.Path):
        """Mark file as uploaded"""
        p = path.parent / f".{path.name}.up"
        p.touch()



def main():
    """Main entry point"""
    ClientTool().run()

if __name__ == "__main__":
    ClientTool().run()
