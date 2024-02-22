import asyncio
import hmac
import json
import logging
import os
import pathlib
import tempfile
import traceback
from typing import Dict, Tuple, List

from aiohttp import web, WSMsgType

from tcsfw.client_api import ClientAPI, APIRequest, APIListener
from tcsfw.model import Host, Connection, IoTSystem


class Session(APIListener):
    """A session per web socket"""
    def __init__(self, server: 'HTTPServerRunner', socket: web.WebSocketResponse, request: APIRequest):
        self.server = server
        self.socket = socket
        self.original_request = request
        self.subscribed = False  # subscribed?
        self.server.api.api_listener.append((self, self.original_request))

    def systemReset(self, data: Dict, system: IoTSystem):
        if self.subscribed:
            self.server.dump_model(self)

    def connectionChange(self, data: Dict, connection: Connection):
        if self.subscribed:
            self.server.send_queue.put_nowait((self, data))

    def hostChange(self, data: Dict, host: Host):
        if self.subscribed:
            self.server.send_queue.put_nowait((self, data))

    def close(self):
        self.subscribed = False
        self.server.api.api_listener.remove((self, self.original_request))


class HTTPServerRunner:
    """Run HTTP server locally"""
    PATH = pathlib.Path("html")

    def __init__(self, api: ClientAPI, base_directory=pathlib.Path("."), port=8180, no_auth_ok=False):
        self.api = api
        self.registry = api.registry
        self.logger = logging.getLogger("server")
        self.sample_path = base_directory / "sample"
        self.host = "127.0.0.1"
        self.port = port
        self.auth_token = os.environ.get("TCSFW_SERVER_API_KEY", "")
        if not self.auth_token and not no_auth_ok:
            raise Exception("No environment variable TCSFW_SERVER_API_KEY (use --no-auth-ok to skip check)")
        self.component_delay = 0
        self.sessions: List[Session] = []
        self.loop = asyncio.get_event_loop()
        self.send_queue: asyncio.Queue[Tuple[Session, Dict]] = asyncio.Queue()
        self.send_queue_target_size = 10
        self.process_tasks = asyncio.Event()

    def run(self):
        """Start sync loop and run the server"""
        self.loop.run_until_complete(self.start_server())
        self.loop.create_task(self.registry_worker())
        self.loop.create_task(self.send_worker())
        self.loop.run_forever()
        # registry must be indirect
        self.registry.fallthrough = False

    async def start_server(self):
        """Start the Web server"""
        app = web.Application()
        app.add_routes([
            web.get('/api1/ws/{tail:.+}', self.handle_ws),  # must be first
            web.get('/api1/{tail:.+}', self.handle_http),
            web.post('/api1/{tail:.+}', self.handle_http),
        ])
        rr = web.AppRunner(app)
        await rr.setup()
        site = web.TCPSite(rr, self.host, self.port)
        self.logger.info(f"HTTP server running at {self.host}:{self.port}...")
        await site.start()

    async def registry_worker(self):
        """A worker for registry tasks"""
        while True:
            await self.process_tasks.wait()
            if self.send_queue.qsize() > self.send_queue_target_size:
                more = False  # wait more stuff to be sent
            else:
                more = self.registry.do_task()
            if not more:
                self.process_tasks.clear()

    async def send_worker(self):
        """A worker to send data to websockets"""
        while True:
            session, d = await self.send_queue.get()
            if session.subscribed:
                self.logger.info("send %s", d)
                await session.socket.send_json(d)
            self.send_queue.task_done()
            if self.component_delay > 0:
                # artificial delay for testing
                await asyncio.sleep(self.component_delay)
            self.process_tasks.set()

    async def update_registry(self):
        """More tasks have been added"""
        self.process_tasks.set()

    def check_permission(self, request):
        """Check permissions"""
        auth_t = request.headers.get("x-authorization", "").strip()
        if not auth_t:
            auth_t = request.cookies.get("authorization", "").strip()
        if not auth_t:
            if self.auth_token:
                raise PermissionError("No authentication token provided")
        else:
            # compare token constant time to avoid timing attacks
            token_1 = auth_t.encode("utf-8")
            token_2 = self.auth_token.encode("utf-8")
            if not hmac.compare_digest(token_1, token_2):
                 raise PermissionError("Invalid API key")

    async def handle_http(self, request):
        """Handle normal HTTP GET or POST request"""
        try:
            self.check_permission(request)

            assert request.path_qs.startswith("/api1/")
            req = APIRequest.parse(request.path_qs[6:])
            self.logger.info("API: %s %s", request.method, req)
            if request.method == "GET":
                res = self.api.api_get(req)
            elif request.method == "POST":
                # read all data as easy solution to async problem
                r_size = 0
                with tempfile.TemporaryFile() as tmp:
                    b = await request.content.read(1024)
                    while b:
                        tmp.write(b)
                        r_size += len(b)
                        b = await request.content.read(1024)
                    tmp.seek(0)
                    res = self.api.api_post(req, tmp if r_size > 0 else None)

            else:
                raise NotImplementedError("Unexpected method/path")
            await self.update_registry()
            return web.Response(text=json.dumps(res))
        except NotImplementedError:
            return web.Response(status=400)
        except FileNotFoundError:
            return web.Response(status=404)
        except PermissionError:
            return web.Response(status=401)
        except Exception:
            traceback.print_exc()
            return web.Response(status=500)

    async def handle_ws(self, request):
        """Handle websocket HTTP request"""
        assert request.path_qs.startswith("/api1/ws/")
        req = APIRequest.parse(request.path_qs[9:])
        self.logger.info("WS: %s", req)
        if req.path != "model/subscribe":  # the only function
            return web.Response(status=404)
        req = req.change_path(".")  # we can only subscribe all

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            self.check_permission(request)
        except PermissionError:
            # no permission to proceed, communicate error using WS
            await ws.close(code=4401, message=b"Permission check failed")  # 4000 + HTTP code
            self.logger.warning('Permission check failed')
            return

        self.logger.info('WS loop started')

        session = Session(self, ws, req)
        # initial model
        # do not async so that no updates between getting model and putting it to the queue
        session.subscribed = True
        if req.parameters.get("load_all", "").lower() != "false":  # can avoid JSON dump for debugging
            self.dump_model(session)
        self.sessions.append(session)

        async def receive_loop():
            # we expect nothing from client
            while True:
                msg = await ws.receive()
                if msg.type == WSMsgType.CLOSE:
                    self.logger.info("WS close")
                    break
                else:
                    self.logger.warning("Unexpected WS type %d", msg.type)
        try:
            await receive_loop()
        finally:
            session.close()  # drop remaining sends
            self.sessions.remove(session)
        return ws

    def dump_model(self, session: Session):
        """Dump the whole model into a session"""
        if not session.subscribed:
            return
        for d in self.api.api_iterate_all(session.original_request):
            self.send_queue.put_nowait((session, d))
