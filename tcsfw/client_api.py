"""Client API implementation"""

import io
import json
import logging
import os
import pathlib
import shutil
import traceback
import urllib
from typing import Dict, List, Tuple, Any, Iterable, BinaryIO, Optional
import prompt_toolkit
from prompt_toolkit.history import FileHistory

from tcsfw.basics import Status
from tcsfw.batch_import import BatchImporter
from tcsfw.verdict import Verdict
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.coverage_result import CoverageReport
from tcsfw.entity import Entity
from tcsfw.event_interface import EventMap
from tcsfw.model import Addressable, NetworkNode, Connection, Host, Service, ModelListener, IoTSystem, NodeComponent
from tcsfw.property import Properties, PropertyKey, PropertySetValue, PropertyVerdictValue
from tcsfw.registry import Registry
from tcsfw.specifications import Specifications
from tcsfw.traffic import NO_EVIDENCE
from tcsfw.verdict import Verdictable

# format strings
FORMAT_YEAR_MONTH_DAY = "%Y-%m-%d"


class APIRequest:
    """API request details"""
    def __init__(self, path: str):
        self.path = path
        self.parameters: Dict[str, str] = {}
        self.get_connections = False
        self.get_visual = False

    @classmethod
    def parse(cls, url_str: str) -> 'APIRequest':
        """Parse URL string into API request object"""
        url = urllib.parse.urlparse(url_str)
        path = url.path
        req = APIRequest(path)
        qs = urllib.parse.parse_qs(url.query)
        for k, vs in qs.items():
            req.parameters[k] = "".join(vs)
        req.get_visual = "visual" in qs  # Assumes we have VisualAPI
        return req

    def change_path(self, path: str) -> 'APIRequest':
        """Change the path"""
        r = APIRequest(path)
        r.parameters.update(self.parameters)
        r.get_connections = self.get_connections
        r.get_visual = self.get_visual
        return r

    def __repr__(self):
        return self.path


class APIListener:
    """Model change listener through API"""
    def note_system_reset(self, data: Dict, _system: IoTSystem):
        """System reset event"""
        self.note_event(data)

    def note_connection_change(self, data: Dict, _connection: Connection):
        """Connection change event"""
        self.note_event(data)

    def note_host_change(self, data: Dict, _host: Host):
        """Host change event"""
        self.note_event(data)

    def note_address_change(self, data: Dict, _host: Host):
        """Address change event"""
        self.note_event(data)

    def note_property_change(self, data: Dict, _entity: Entity):
        """Property change event"""
        self.note_event(data)

    def note_evidence_change(self, data: Dict):
        """Evidence change event"""
        self.note_event(data)

    def note_event(self, _data: Dict):
        """Any API event"""

class RequestContext:
    """API request context"""
    def __init__(self, request: APIRequest, api: 'ClientAPI'):
        self.request = request
        self.api = api

    def change_path(self, path: str) -> 'RequestContext':
        """Change the path"""
        c = RequestContext(self.request.change_path(path), self.api)
        return c


class ClientAPI(ModelListener):
    """Client API implementation"""
    def __init__(self, registry: Registry, claims: RequirementClaimMapper):
        self.registry = registry
        self.claim_coverage = claims
        self.logger = logging.getLogger("api")
        self.api_listener: List[Tuple[APIListener, APIRequest]] = []
        registry.system.model_listeners.append(self)
        # API aggregates verdicts from children into parents, keep track
        self.verdict_cache: Dict[Entity, Verdict] = {}
        # local IDs strings for entities and connections
        self.ids: Dict[Any, str] = {}

    def api_get(self, request: APIRequest) -> Dict:
        """Get API data"""
        context = RequestContext(request, self)
        path = request.path
        if path == "all":
            request.get_connections = False
            return {"events" : list(self.api_iterate_all(request.change_path(".")))}
        if path.startswith("coverage"):
            return self.get_coverage(context.change_path(path[8:]))
        if path.startswith("host/"):
            _, r = self.get_entity(self.registry.system, context.change_path(path[5:]))
            return r
        if path.startswith("log"):
            ps = request.parameters
            r = self.get_log(ps.get("entity", ""), ps.get("key", ""))
            return r
        raise FileNotFoundError("Bad API request")

    def api_post(self, request: APIRequest, data: Optional[BinaryIO]) -> Dict:
        """Post API data"""
        path = request.path
        r = {}
        if path == "reset":
            param = json.load(data) if data else {}
            self.system_reset(param.get("evidence", {}), include_all=param.get("include_all", False))
            if param.get("dump_all", False):
                r = {"events": list(self.api_iterate_all(request.change_path(".")))}
        elif path.startswith("event/"):
            e_name = path[6:]
            e_type = EventMap.get_event_class(e_name)
            if e_type is None:
                raise FileNotFoundError(f"Unknown event type {e_name}")
            js = json.load(data) if data else {}
            e = e_type.decode_data_json(NO_EVIDENCE, js, self.get_by_id)
            self.registry.consume(e)
        else:
            raise FileNotFoundError("Unknown API endpoint")
        return r

    def api_post_file(self, request: APIRequest, data_file: pathlib.Path) -> Dict:
        """Post API data in ZIP file"""
        path = request.path
        if path != "batch":
            raise FileNotFoundError("Unknown API endpoint")
        old_evidence = self.registry.all_evidence.copy()
        importer = BatchImporter(self.registry)
        importer.import_batch(data_file)
        if old_evidence != self.registry.all_evidence:
            # batch import can bring new evdence sources, send evidence change event
            change_event = {"evidence": self.get_evidence_filter()}
            for ln, _ in self.api_listener:
                ln.note_evidence_change(change_event)
        return {}

    def system_reset(self, filter_list: Dict, include_all: bool = False):
        """Reset, set new evidence filter and reset the model"""
        fs = {ev.label: ev for ev in self.registry.all_evidence}
        e_filter = {}
        for fn, sel in filter_list.items():
            ev = fs.get(f"{fn}")
            if ev:
                e_filter[ev] = sel
        self.registry.reset(e_filter, include_all)
        self.verdict_cache.clear()
        # API reset event
        for ln, req in self.api_listener:
            context = RequestContext(req, self)
            d = self.get_system_info(context)
            ln.note_system_reset({"system": d}, self.registry.system)
        # reapply all events after reset
        self.registry.apply_all_events()

    def get_log(self, entity="", key="") -> Dict:
        """Get log"""
        rs = {}
        if entity:
            e = self.get_by_id(entity)
            if e is None:
                raise FileNotFoundError(f"Invalid entity {entity}")
            rs["id"] = self.get_id(e)
            k = PropertyKey.parse(key) if key else None
            if k:
                rs["property"] = f"{k}"
            logs = self.registry.logging.get_log(e, k)
        else:
            logs = self.registry.logging.get_log()
        if key:
            rs["property"] = key
        rs["logs"] = lr = []
        for lo in logs:
            ev = lo.event
            ent = lo.entity
            ls = {
                "source": ev.evidence.source.name,
                "info": ev.get_info(),
                "ref": ev.evidence.get_reference(),
                "entity": ent.long_name() if ent else "",
            }
            if lo.property_value:
                ls["property"] = f"{lo.property_value[0]}"
            lo_v = ev.get_verdict() if isinstance(ev, Verdictable) else Verdict.INCON
            if lo_v != Verdict.INCON:
                ls["verdict"] = ev.get_verdict().value
            lr.append(ls)
        return rs

    def get_status_verdict(self, status: Status, verdict: Verdict) -> Dict:
        """Get status and verdict for an entity"""
        return f"{status.value}/{verdict.value}"

    def get_properties(self, properties: Dict[PropertyKey, Any], json_dict: Dict = None) -> Dict:
        """Get properties"""
        cs = {} if json_dict is None else json_dict
        for key, p  in properties.items():
            if key == Properties.EXPECTED:
                continue  # this property is shown by status
            vs = {
                "name": key.get_name(short=True),
            }
            if isinstance(p, PropertyVerdictValue):
                vs["verdict"] = p.verdict.value
                vs["info"] = p.explanation or key.get_name()
            elif isinstance(p, PropertySetValue):
                vs["verdict"] = p.get_overall_verdict(properties).value
                vs["info"] = p.explanation or key.get_name()
                vs["checks"] = sorted([f"{k}" for k in p.sub_keys])
            else:
                vs["verdict"] = ""  # no verdict
                vs["info"] = f"{p}"
            cs[key.get_name()] = vs
        return cs

    def get_components(self, entity: NetworkNode, _context: RequestContext) -> Iterable[Tuple[NodeComponent, Dict]]:
        """Get components of an entity"""
        def sub(component: NodeComponent) -> Dict:
            com_cs = {
                "name": component.name,
                "id": self.get_id(component),
                "node_id": self.get_id(entity),
                "status": self.get_status_verdict(component.status, component.get_verdict(self.verdict_cache)),
            }
            if component.sub_components:
                com_cs["sub_components"] = [sub(c) for c in component.sub_components]
            return component, com_cs

        root_list = []
        for com in entity.components:
            root_list.append(sub(com))
        return root_list

    def get_entity(self, parent: NetworkNode, context: RequestContext) -> Tuple[NetworkNode, Dict]:
        """Get entity data by path"""
        path = context.request.path
        if path == ".":
            entity = parent
        else:
            name = path
            if "/" in path:
                name = name[path.index("/")]
            entity = parent.get_entity(name)
            if not entity:
                raise FileNotFoundError(f"Parent '{parent.name}' does not have child '{name}'")
            r_tail = path[len(name) + 1:]
            if r_tail:
                _, r = self.get_entity(entity, context.change_path(r_tail))
                return entity, r
        context = context.change_path(".")
        r = {
            "name": entity.name,
            "id": self.get_id(entity),
            "description": entity.description,
            "addresses": sorted([f"{a}" for a in entity.addresses]),
            "status": self.get_status_verdict(entity.status, entity.get_verdict(self.verdict_cache)),
        }
        if entity.is_multicast():
            r["type"] = "Broadcast"  # special type
        elif isinstance(entity, Service):
            r["type"] = entity.con_type.value  # service type by connection
            if entity.client_side:
                r["client_side"] = True
        else:
            r["type"] = entity.host_type.value  # host type by function

        host = entity.get_parent_host()
        if host != entity:
            r["host_id"] = self.get_id(host)
        if isinstance(entity.parent, Addressable):
            r["parent_id"] = self.get_id(entity.parent)
        return entity, r

    def get_connection(self, connection: Connection, _context: RequestContext) -> Dict:
        """GET connection"""
        def location(entity: NetworkNode) -> List[str]:
            if isinstance(entity, Addressable):
                loc = location(entity.parent)
                loc.append(entity.name)
                return loc
            return []

        s, t = connection.source, connection.target
        cr = {
            "id": f"{self.get_id(connection)}",
            "source": location(s),
            "source_id": self.get_id(s),
            "source_host_id": self.get_id(s.get_parent_host()),
            "target": location(t),
            "target_id": self.get_id(t),
            "target_host_id": self.get_id(t.get_parent_host()),
            "status": self.get_status_verdict(connection.status, connection.get_verdict(self.verdict_cache)),
            "type": connection.con_type.value,
        }
        return cr

    def get_system_info(self, _context: RequestContext) -> Dict:
        """Get system information"""
        s = self.registry.system
        si = {
            "id": self.get_id(s),
            "system_name": s.name,
        }
        return si

    def get_evidence_filter(self) -> Dict:
        """Get evidence filter"""
        r = {}
        ev_filter = self.registry.evidence_filter
        for ev in sorted(self.registry.all_evidence, key=lambda x: x.label):
            filter_v = ev_filter.get(ev.label, False)
            sr = r[ev.label] = {
                "name": ev.name,
                "selected": filter_v
            }
            if ev.timestamp is not None:
                sr["time_s"] = ev.timestamp.strftime(FORMAT_YEAR_MONTH_DAY)
        return r

    def get_coverage(self, context: RequestContext) -> Dict:
        """Get coverage data as JSON"""
        path = context.request.path
        spec_name = path[1:] if path.startswith("/") else ""
        spec = Specifications.get_specification(spec_name)
        report = CoverageReport(self.registry.logging, self.claim_coverage)
        js = report.json(specification=spec)
        js["system"] = self.get_system_info(context)
        return js


    def _yield_property_update(self, entity: Entity) -> Iterable[Dict]:
        """Yield property update, if properites to show"""
        pr = self.get_properties(entity.properties)
        if not pr:
            return
        r = { "update": {
            "id": self.get_id(entity),
            "properties": pr
        }}
        yield r

    def api_iterate_all(self, request: APIRequest) -> Iterable[Dict]:
        """Iterate all model entities and connections"""
        context = RequestContext(request, self)
        system = self.registry.system
        request.get_connections = False
        # start with reset, client should clear all entity and connection information
        yield {"reset": {}}
        yield {"system": self.get_system_info(context)}
        yield from self._yield_property_update(system)
        # ... as we list it here then
        for h in system.get_hosts():
            if h.status != Status.PLACEHOLDER:
                _, hr = self.get_entity(h, context)
                yield {"host": hr}
                for com, com_r in self.get_components(h, context):
                    yield {"component": com_r}
                    yield from self._yield_property_update(com)
                yield from self._yield_property_update(h)
                for c in h.children:
                    _, cr = self.get_entity(c, context)
                    yield {"service": cr}
                    yield from self._yield_property_update(c)
        for c in self.registry.system.get_connections():
            cr = self.get_connection(c, context)
            yield {"connection": cr}
            yield from self._yield_property_update(c)
        yield {"evidence": self.get_evidence_filter()}

    def get_by_id(self, id_string: str) -> Optional[Any]:
        """Get entity by id string"""
        _, _, i = id_string.partition("-")
        return self.registry.get_entity(int(i))

    def get_id(self, entity) -> str:
        """Get ID for an entity prefixed by type"""
        # Must be valid as DOM class or id
        int_id = self.registry.get_id(entity)
        if isinstance(entity, Host):
            p = "host"
        elif isinstance(entity, Service):
            p = "service"
        elif isinstance(entity, Connection):
            p = "conn"
        elif isinstance(entity, NodeComponent):
            p = "com"
        elif isinstance(entity, IoTSystem):
            p = "system"
        else:
            raise ValueError(f"Unknown entity type {type(entity)}")
        return f"{p}-{int_id}"

    def connection_change(self, connection: Connection):
        if not connection.is_relevant(ignore_ends=True):
            return
        for ln, req in self.api_listener:
            context = RequestContext(req, self)
            d = self.get_connection(connection, context)
            ln.note_connection_change({"connection": d}, connection)
        # check if connection ends have changed status
        self._find_verdict_changes(connection.source)
        self._find_verdict_changes(connection.target)

    def host_change(self, host: Host):
        for ln, req in self.api_listener:
            context = RequestContext(req.change_path("."), self)
            _, d = self.get_entity(host, context)
            ln.note_host_change({"host": d}, host)

    def address_change(self, host: Host):
        d = {
            "host_id": self.get_id(host),
            "host_name": host.long_name(),  # to help reading JSON events
            "addresses": sorted([f"{a}" for a in host.addresses])
        }
        for ln, _ in self.api_listener:
            ln.note_address_change({"address": d}, host)

    def service_change(self, service: Service):
        for ln, req in self.api_listener:
            context = RequestContext(req.change_path("."), self)
            _, d = self.get_entity(service, context)
            ln.note_host_change({"service": d}, service)
        # service affect parent verdict
        self._find_verdict_changes(service.get_parent_host())

    def property_change(self, entity: Entity, value: Tuple[PropertyKey, Any]):
        props = self.get_properties({value[0]: value[1]})
        d = {
            "id": self.get_id(entity),
            "ent_name": entity.long_name(),  # to help reading JSON events
        }
        # check if status change
        old_v = self.verdict_cache.pop(entity, None)
        if old_v is not None:
            new_v = entity.get_verdict(self.verdict_cache)
            if new_v != old_v:
                d["status"] = self.get_status_verdict(entity.status, new_v)
                if isinstance(entity, Service):
                    # check if parent verdict changed, too
                    self._find_verdict_changes(entity.get_parent_host())
        if props:
            d["properties"] = props
        js = {"update": d}
        for ln, _ in self.api_listener:
            ln.note_property_change(js, entity)
        self._find_verdict_changes(entity)

    def _find_verdict_changes(self, entity: Entity):
        """Find parent verdict changes and send updates, as required"""
        old_v = self.verdict_cache.pop(entity, None)
        new_v = entity.get_verdict(self.verdict_cache)
        if old_v is None or new_v == old_v:
            return  # new entity or no change -> no update
        js = {"update": {
            "id": self.get_id(entity),
            "ent_name": entity.long_name(),  # to help reading JSON events
            "status": self.get_status_verdict(entity.status, new_v),
        }}
        for ln, _ in self.api_listener:
            ln.note_property_change(js, entity)
        if isinstance(entity, Service):
            # check if parent verdict changed, too
            self._find_verdict_changes(entity.get_parent_host())

class ClientPrompt(APIListener):
    """A prompt to interact with the model"""
    def __init__(self, api: ClientAPI):
        self.api = api
        # find out screen dimensions
        self.screen_height = shutil.get_terminal_size()[1]
        # iterate all entities to create IDs for them (yes, a hack)
        list(api.api_iterate_all(APIRequest(".")))
        # session with history
        history_file = os.path.expanduser("~/.tcsfw_prompt_history")
        self.session = prompt_toolkit.PromptSession(history=FileHistory(history_file))
        # current output buffer
        self.buffer = []
        self.buffer_index = 0
        # listen for events
        api.api_listener.append((self, APIRequest(".")))

    def prompt_loop(self):
        """Prompt loop"""

        def print_lines(start_line: int) -> int:
            start_line = max(0, start_line)
            show_lines = min(self.screen_height - 1, len(self.buffer) - start_line)
            print("\n".join(self.buffer[start_line:start_line + show_lines]))
            return start_line + show_lines

        while True:
            # read a line from stdin
            line = self.session.prompt("tcsfw> ").strip()
            if not line:
                continue
            if line in {"quit", "q"}:
                break
            if line in {"next", "n"}:
                self.buffer_index = print_lines(self.buffer_index)
                continue
            if line in {"prev", "p"}:
                self.buffer_index = print_lines(self.buffer_index - 2 * (self.screen_height + 1))
                continue
            if line in {"top", "t"}:
                self.buffer_index = print_lines(0)
                continue
            if line in {"end", "e"}:
                self.buffer_index = print_lines(len(self.buffer) - self.screen_height + 1)
                continue
            try:
                # format method and arguments
                parts = line.partition(" ")
                method = parts[0].lower()
                args = parts[2]
                self.buffer.clear() # collect new output
                if method in {"get", "g"}:
                    req = APIRequest.parse(args)
                    self.buffer = []
                    out = json.dumps(self.api.api_get(req), indent=2)
                elif method in {"post", "p"}:
                    parts = args.partition(" ")
                    req = APIRequest.parse(parts[0])
                    data = parts[2] if parts[2] else None
                    bin_data = None if data is None else io.BytesIO(data.encode())
                    self.buffer = []
                    out = json.dumps(self.api.api_post(req, bin_data), indent=2)
                else:
                    print(f"Unknown method {method}")
                    continue
                self.buffer.extend(out.split("\n"))
                show_lines = min(self.screen_height - 1, len(self.buffer))
                print("\n".join(self.buffer[:show_lines]))
                self.buffer_index = show_lines
            except Exception:  # pylint: disable=broad-except
                # print full stack trace
                traceback.print_exc()

    def note_event(self, data: Dict):
        self.buffer.extend(json.dumps(data).split("\n"))
