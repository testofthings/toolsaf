import json
import logging
import urllib
from typing import Dict, List, Tuple, Any, Iterable, BinaryIO, Optional

from framing.raw_data import Raw

from tcsfw.address import AnyAddress, HWAddress, HWAddresses, IPAddresses, Protocol, IPAddress
from tcsfw.basics import Verdict
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.coverage_result import CoverageReport
from tcsfw.entity import Entity
from tcsfw.model import Addressable, NetworkNode, Connection, Host, Service, ModelListener, IoTSystem, NodeComponent
from tcsfw.pcap_reader import PCAPReader
from tcsfw.property import PropertyKey, PropertySetValue, PropertyVerdictValue
from tcsfw.registry import Registry
from tcsfw.result import Report
from tcsfw.traffic import Evidence, NO_EVIDENCE, Flow, IPFlow
from tcsfw.verdict import Status, Verdictable

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
    def systemReset(self, data: Dict, system: IoTSystem):
        pass

    def connectionChange(self, data: Dict, connection: Connection):
        pass

    def hostChange(self, data: Dict, host: Host):
        pass


class RequestContext:
    def __init__(self, request: APIRequest, api: 'ClientAPI'):
        self.request = request
        self.api = api

        self.verdict_cache: Dict[Entity, Verdict] = {}

    def change_path(self, path: str) -> 'RequestContext':
        """Change the path"""
        c = RequestContext(self.request.change_path(path), self.api)
        c.verdict_cache = self.verdict_cache
        return c


class ClientAPI(ModelListener):
    """API for clients"""
    def __init__(self, registry: Registry, claims: RequirementClaimMapper):
        self.registry = registry
        self.claim_coverage = claims
        self.logger = logging.getLogger("api")
        self.api_listener: List[Tuple[APIListener, APIRequest]] = []
        registry.system.model_listeners.append(self)
        # local IDs strings for entities and connections
        self.ids: Dict[Any, str] = {}

    def parse_flow(self, evidence: Evidence, data: Dict) -> Tuple[Flow, str]:
        """Parse flow"""
        s = (
            HWAddress.new(data["source-hw"]) if "source-hw" in data else HWAddresses.NULL,
            IPAddress.new(data["source-ip"]) if "source-ip" in data else IPAddresses.NULL,
            int(data["source-port"]) if "source-port" in data else 0,
        )
        t = (
            HWAddress.new(data["target-hw"]) if "target-hw" in data else HWAddresses.NULL,
            IPAddress.new(data["target-ip"]) if "target-ip" in data else IPAddresses.NULL,
            int(data["target-port"]) if "target-port" in data else 0,
        )
        ref = data.get("ref", "")
        return IPFlow(evidence, s, t, Protocol[data["protocol"] if "protocol" in data else Protocol.ANY]), ref

    def api_get(self, request: APIRequest) -> Dict:
        """Get API data"""
        context = RequestContext(request, self)
        path = request.path
        if path == "model":
            request.get_connections = False
            return self.get_model(context.change_path("."))
        elif path.startswith("coverage"):
            return self.get_coverage(context.change_path(path[8:]))
        elif path.startswith("host/"):
            _, r = self.get_entity(self.registry.system, context.change_path(path[5:]))
            return r
        elif path.startswith("log"):
            ps = request.parameters
            r = self.get_log(ps.get("entity", ""), ps.get("key", ""))
            return r
        else:
            raise FileNotFoundError("Bad API request")

    def api_post(self, request: APIRequest, data: Optional[BinaryIO]) -> Dict:
        """Post API data"""
        path = request.path
        r = {}
        if path == "reset":
            param = json.load(data) if data else {}
            self.post_evidence_filter(param.get("evidence", {}), include_all=param.get("include_all", False))
        elif path == "flow":
            flow, ref = self.parse_flow(NO_EVIDENCE, json.load(data))
            self.registry.connection(flow)
        # NOTE: We would need DNS service instance
        # elif path == "name":
        #     js = json.load(data)
        #     self.registry.name(
        #         NameEvent(NO_EVIDENCE, js["name"], address=IPAddress.new(js["address"]) if "address" in js else None))
        elif path == "capture":
            raw = Raw.stream(data)
            count = PCAPReader(self.registry.system).parse(raw)
            r = {"frames": count, "bytes": raw.bytes_available()}
        else:
            raise NotImplementedError("Bad API request")
        return r

    def post_evidence_filter(self, filter_list: Dict, include_all: bool = False):
        """Post new evidence filter and reset the model"""
        fs = {ev.label: ev for ev in self.registry.all_evidence}
        e_filter = {}
        for fn, sel in filter_list.items():
            ev = fs.get(f"{fn}")
            if ev:
                e_filter[ev] = sel
        self.registry.reset(e_filter, include_all)

    def get_log(self, entity="", key="") -> Dict:
        """Get log"""
        rs = {}
        if entity:
            e = self.get_by_id(entity)
            if e is None:
                raise FileNotFoundError(f"Invalid entity {entity}")
            rs["id"] = self.get_id(e),
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
            if lo.property:
                ls["property"] = f"{lo.property[0]}"
            lo_v = ev.get_verdict() if isinstance(ev, Verdictable) else Verdict.INCON
            if lo_v != Verdict.INCON:
                ls["verdict"] = ev.get_verdict().value
            lr.append(ls)
        return rs

    def get_status_verdict(self, status: Status, verdict: Verdict) -> Dict:
        """Get status and verdict for an entity"""
        return f"{status.value}/{verdict.value}"

    def get_properties(self, properties: Dict[PropertyKey, Any]) -> Dict:
        """Get properties"""
        cs = {}
        for key, p  in properties.items():
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

    def get_components(self, entity: NetworkNode, context: RequestContext) -> List:
        def sub(component: NodeComponent) -> Dict:
            # if isinstance(component, Software):
                # FIXME - putting in release info even without claims for it
                # info = component.info
                # claim_d = Claim.identifier_map(claims)
                # if info.first_release and not FirstRelease.find(claim_d):
                #     c = FirstRelease(info.first_release)
                #     claims[c] = ClaimStatus(c, verdict=Verdict.EXTERNAL)
                # if info.latest_release_name and info.latest_release and not LatestRelease.find(claim_d):
                #     c = LatestRelease(info.latest_release_name, info.latest_release)
                #     claims[c] = ClaimStatus(c, verdict=Verdict.EXTERNAL)
                # if info.interval_days is not None and not ReleaseInterval.find(claim_d):
                #     c = ReleaseInterval(info.interval_days)
                #     claims[c] = ClaimStatus(c, verdict=Verdict.EXTERNAL)
            com_cs = {
                "name": component.name,
                "id": self.get_id(component),
                "status": self.get_status_verdict(component.status, component.get_verdict(context.verdict_cache)),
                "properties": self.get_properties(component.properties)
            }
            if component.sub_components:
                com_cs["sub_components"] = [sub(c) for c in component.sub_components]
            return com_cs

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
                raise FileNotFoundError(f"Parent '{parent.name}' does not have that child")
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
            "status": self.get_status_verdict(entity.status, entity.get_verdict(context.verdict_cache)),
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
        if entity.children:
            r["services"] = [self.get_entity(c, context)[1]
                             for c in entity.children if c.status != Status.PLACEHOLDER]
        if entity.components:
            r["components"] = self.get_components(entity, context)
        if isinstance(entity, Host):
            if context.request.get_connections:
                cj: List[Dict] = r.setdefault("connections", [])
                for c in entity.connections:
                    if c.is_relevant(ignore_ends=True):
                        cj.append(self.get_connection(c, context))
        r["properties"] = self.get_properties(entity.properties)
        return entity, r

    def get_connection(self, connection: Connection, context: RequestContext) -> Dict:
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
            "status": self.get_status_verdict(connection.status, connection.get_verdict(context.verdict_cache)),
            "type": connection.con_type.value,
            "properties": self.get_properties(connection.properties),
        }
        return cr

    def get_system_info(self, context: RequestContext) -> Dict:
        """Get system information"""
        s = self.registry.system
        si = {
            "system_name": s.name,
            "components": self.get_components(s, context),
            # "checks": self.get_checks(s.status, s.claims),
        }
        return si

    def get_model(self, context: RequestContext) -> Dict:
        """Get whole model"""
        system = self.registry.system
        root: Dict[str, Any] = {
            "reset": {},
            "system": self.get_system_info(context)
        }
        hj = root.setdefault("hosts", [])
        for h in system.get_hosts():
            if h.status != Status.PLACEHOLDER:
                _, hr = self.get_entity(h, context)
                hj.append(hr)
        cj = root.setdefault("connections", [])
        for c in self.registry.system.get_connections():
            cr = self.get_connection(c, context)
            cj.append(cr)
        root["evidence"] = self.get_evidence_filter()
        return root

    def get_evidence_filter(self) -> Dict:
        """Get evidence filter"""
        r = {}
        for ev in sorted(self.registry.all_evidence, key=lambda x: x.label):
            filter_v = self.registry.trail_filter.get(ev.label, False)
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
        spec = CoverageReport.load_specification(spec_name)
        report = CoverageReport(self.registry.logging, self.claim_coverage)
        js = report.json(specification=spec)
        js["system"] = self.get_system_info(context)
        return js

    def api_iterate_all(self, request: APIRequest) -> Iterable[Dict]:
        """Iterate all model entities and connections"""
        context = RequestContext(request, self)
        system = self.registry.system
        request.get_connections = False
        # start with reset, client should clear all entity and connection information
        its = [
            {"reset": {}},
            {"system": self.get_system_info(context)},
        ]
        # ... as we list it here then
        for h in system.get_hosts():
            if h.status != Status.PLACEHOLDER:
                _, hr = self.get_entity(h, context)
                its.append({"host": hr})
        for c in self.registry.system.get_connections():
            cr = self.get_connection(c, context)
            its.append({"connection": cr})
        its.append({"evidence": self.get_evidence_filter()})
        return its

    def get_by_id(self, id_string: str) -> Optional:
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
        else:
            raise Exception("Unknown entity type %s", type(entity))
        return f"{p}-{int_id}"

    def systemReset(self, system: IoTSystem):
        for ln, req in self.api_listener:
            context = RequestContext(req, self)
            d = self.get_system_info(context)
            ln.systemReset({"system": d}, system)

    def connectionChange(self, connection: Connection):
        if not connection.is_relevant(ignore_ends=True):
            return
        for ln, req in self.api_listener:
            context = RequestContext(req, self)
            d = self.get_connection(connection, context)
            ln.connectionChange({"connection": d}, connection)

    def hostChange(self, host: Host):
        for ln, req in self.api_listener:
            context = RequestContext(req.change_path("."), self)
            _, d = self.get_entity(host, context)
            ln.hostChange({"host": d}, host)

