"""Lauch model given from command-line"""

import asyncio
import logging
import os
import argparse
import pathlib
import re
import secrets
import subprocess
import sys
import traceback
from typing import Dict, Set, Tuple

import aiofiles
from aiohttp import web

from tcsfw.client_api import APIRequest
from tcsfw.command_basics import get_authorization

# pylint: disable=duplicate-code  # web server code is similar in two places

class Launcher:
    """Lister for requests and launch models as separate processes"""
    def __init__(self):
        parser = argparse.ArgumentParser(description='Launcher script')
        parser.add_argument("--listen-port", "-p", type=int,
                            help="Listen HTTP requests at port")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)
        parser.add_argument("--no-db", action="store_true",
                            help="Do not use DB storage", default=None)
        args = parser.parse_args()

        self.logger = logging.getLogger("launcher")
        logging.basicConfig(format='%(message)s', level=getattr(logging, args.log_level or 'INFO'))

        # NOTE: Nginx accepts port range 10000-19999
        self.client_port_range = (10000, 11000)
        self.clients: Set[int] = set()
        self.connected: Dict[Tuple[str, str], int] = {}  # key: user, app
        self.api_keys: Dict[str, str] = {}
        self.api_key_reverse: Dict[str, str] = {}

        self.db_base_dir = None if args.no_db else pathlib.Path("app-dbs")  # create sqlite DBs here

        self.host = None
        self.port = int(args.listen_port or 8180)  # match http server default port
        self.loop = asyncio.get_event_loop()
        self.run()

    def run(self):
        """Start sync loop and run the server"""
        self.loop.run_until_complete(self.start_server())
        self.loop.run_forever()

    async def start_server(self):
        """Start the Web server"""
        app = web.Application()
        app.add_routes([
            web.get('/api1/ping', self.handle_ping),             # ping for health check
            web.get('/login/{tail:.+}', self.handle_login),      # login
            web.get('/api1/proxy/{tail:.+}', self.handle_login), # query proxy configuration
        ])
        rr = web.AppRunner(app)
        await rr.setup()
        site = web.TCPSite(rr, self.host, self.port)
        self.logger.info("HTTP server running at %s:%s...", self.host or "*", self.port)
        await site.start()

    async def handle_ping(self, _request: web.Request):
        """Handle ping request"""
        return web.Response(text="{}")

    async def handle_login(self, request: web.Request):
        """Handle login and loading new endpoint"""
        try:
            if request.method != "GET":
                raise NotImplementedError("Unexpected method")
            use_api_key = False
            if request.path.startswith("/login/statement/"):
                app = request.path[17:]
            elif request.path.startswith("/api1/proxy/statement/"):
                app = request.path[22:]
                use_api_key = True
            else:
                raise FileNotFoundError("Unexpected statement path")

            if use_api_key:
                # API call with API key
                api_key = get_authorization(request)
                if api_key not in self.api_key_reverse:
                    raise PermissionError("Invalid API key")
                user_name = self.api_key_reverse[api_key]
                self.logger.info("Login by valid API key for %s", user_name)
            else:
                # Login to new or logged in application
                user_name = request.headers.get("x-user", "").strip()
                if not user_name:
                    raise PermissionError("No authenticated user name")
                self.logger.info("Login for %s", user_name)
                # API proxy should authenticate access to this endpoint, create a new API key, unless
                # there is a valid one already
                api_key = self.api_keys.get(user_name)
                if not api_key:
                    self.logger.info("Generating new api_key for %s", user_name)
                    api_key = self.generate_api_key(user_name)

            api_req = APIRequest(request).parse(request.path_qs)
            explicit_key = api_req.parameters.get("instance-key")
            app_key = f"{app}/{explicit_key}" if explicit_key else app
            key = user_name, app_key
            api_port = await self.run_process(key, app, api_key=api_key)
            res = {"api_proxy": api_port}

            if not use_api_key:
                # return the generated API key
                res = res.copy()
                res.update({"api_key": api_key})
            return web.json_response(res)
        except NotImplementedError:
            return web.Response(status=400)
        except FileNotFoundError:
            return web.Response(status=404)
        except PermissionError:
            return web.Response(status=401)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            return web.Response(status=500)

    async def run_process(self, key: Tuple[str, str], app: str, api_key: str) -> int:
        """Run process by request, key: user, application"""

        # detect bad characters in the app name or key
        pattern = re.compile(r"[^-a-zA-Z0-9._/ ]")
        for n in (key[0], key[1], app):
            if pattern.findall(n):
                raise FileNotFoundError("Bad name")
            if ".." in n:
                raise FileNotFoundError("Bad name")
        key_str = "#".join(key)

        known_port = self.connected.get(key)
        if known_port:
            return known_port  # already running

        client_port = None
        for port in range(*self.client_port_range):
            if port not in self.clients:
                client_port = port
                break
        else:
            raise FileNotFoundError("No free ports available")
        self.clients.add(client_port)
        self.connected[key] = client_port

        python_app = f"{app}.py"
        if not pathlib.Path(python_app).exists():
            raise FileNotFoundError(f"App not found: {python_app}")

        args = [sys.executable, python_app, "--http-server", f"{client_port}"]
        if self.db_base_dir:
            # use sqlite DB for the app
            db_file = (self.db_base_dir / key[1] / key[0]).with_suffix(".sqlite")
            db_file.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["--db", f"sqlite:///{db_file.as_posix()}"])

        env = os.environ.copy()
        env["TCSFW_SERVER_API_KEY"] = api_key

        # schedule process execution by asyncio and return the port
        process = await asyncio.create_subprocess_exec(*args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        stdout_file = f'stdout-{client_port}.log'
        stderr_file = f'stderr-{client_port}.log'
        stdout_task = asyncio.create_task(self.save_stream_to_file(process.stdout, stdout_file))
        stderr_task = asyncio.create_task(self.save_stream_to_file(process.stderr, stderr_file))

        async def wait_process():
            await process.wait()
            await stdout_task
            await stderr_task
            self.clients.remove(client_port)
            self.connected.pop(key, None)
            self.logger.info("Exit code %s from %s at port %s", process.returncode, key_str, client_port)
            # remove log files
            os.remove(stdout_file)
            os.remove(stderr_file)

        asyncio.create_task(wait_process())

        self.logger.info("Launched %s at port %s", key_str, client_port)
        return client_port

    async def save_stream_to_file(self, stream, file_path):
        """Save data from stream to a file asynchronously"""
        async with aiofiles.open(file_path, 'wb') as f:
            while True:
                chunk = await stream.read(64 * 1024)
                if not chunk:
                    break
                await f.write(chunk)

    def generate_api_key(self, user_name: str) -> str:
        """Generate API key for the user"""
        # get secure random bytes
        key = secrets.token_urlsafe(32)
        self.api_keys[user_name] = key
        self.api_key_reverse[key] = user_name
        return key

if __name__ == "__main__":
    Launcher()
