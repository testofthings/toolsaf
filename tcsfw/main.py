import argparse
import io
import ipaddress
import itertools
import json
import logging
import pathlib
import sys
from typing import Callable, Dict, List, Optional, Self, Tuple, Type, Union

from tcsfw.address import (Addresses, AnyAddress, DNSName, EndpointAddress,
                           HWAddress, HWAddresses, IPAddress, IPAddresses,
                           Protocol)
from tcsfw.batch_import import BatchImporter, LabelFilter
from tcsfw.claim import Claim
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.client_api import APIRequest
from tcsfw.components import (CookieData, Cookies, DataReference, DataStorages,
                              Software)
from tcsfw.coverage_result import CoverageReport
from tcsfw.entity import ClaimAuthority, Entity
from tcsfw.event_interface import PropertyEvent
from tcsfw.events import ReleaseInfo
from tcsfw.http_server import HTTPServerRunner
from tcsfw.inspector import Inspector
from tcsfw.latex_output import LaTeXGenerator
from tcsfw.main_basic import (BuilderInterface, HostInterface, NodeInterface,
                              SoftwareInterface, SubLoader, SystemInterface)
from tcsfw.main_tools import EvidenceLoader, ToolPlanLoader
from tcsfw.model import (Addressable, Connection, ConnectionType,
                         ExternalActivity, Host, HostType, SensitiveData,
                         Service)
from tcsfw.property import Properties, PropertyKey
from tcsfw.registry import Registry
from tcsfw.result import Report
from tcsfw.selector import RequirementSelector
from tcsfw.services import DHCPService, DNSService
from tcsfw.traffic import Evidence, EvidenceSource
from tcsfw.verdict import Status, Verdict
from tcsfw.visualizer import Visualizer, VisualizerAPI


class SystemBuilder(SystemInterface):
    """System model builder"""
    def __init__(self, name="Unnamed system"):
        super().__init__(name)
        self.hosts_by_name: Dict[str, 'HostBuilder'] = {}
        self.entity_by_address: Dict[AnyAddress, 'NodeBuilder'] = {}
        self.network_masks = []
        self.claimSet = ClaimSetBuilder(self)
        self.visualizer = Visualizer()
        self.loaders: List['EvidenceLoader'] = []

    def network(self, mask: str) -> Self:
        """IP network mask"""
        self.network_masks.append(ipaddress.ip_network(mask))
        self.system.ip_networks = self.network_masks
        return self

    def device(self, name="") -> 'HostBuilder':
        """IoT device"""
        name = name or self._free_host_name("Device")
        b = self.get_host_(name, "Internet Of Things device")
        b.entity.host_type = HostType.DEVICE
        return b

    def backend(self, name="") -> 'HostBuilder':
        """Backend service"""
        name = name or self._free_host_name("Backend")
        b = self.get_host_(name, "Backend service over Internet")
        b.entity.host_type = HostType.REMOTE
        return b

    def mobile(self, name="") -> 'HostBuilder':
        """Mobile device"""
        name = name or self._free_host_name("Mobile")
        b = self.get_host_(name, "Mobile application")
        b.entity.host_type = HostType.MOBILE
        b.entity.external_activity = ExternalActivity.UNLIMITED  # who know what apps etc.
        return b

    def browser(self, name="") -> 'HostBuilder':
        """Browser"""
        name = name or self._free_host_name("Browser")
        b = self.get_host_(name, "Browser")
        b.entity.host_type = HostType.BROWSER
        return b

    def any(self, name="", node_type: HostType = None) -> 'HostBuilder':
        """Any host"""
        name = name or self._free_host_name("Host")
        b = self.get_host_(name, "Any host")
        b.entity.any_host = True
        b.entity.host_type = HostType.ADMINISTRATIVE if node_type is None else node_type
        # might serve other network nodes
        b.entity.external_activity = ExternalActivity.UNLIMITED
        return b

    def infra(self, name="") -> 'HostBuilder':
        """Part of the testing infrastructure, not part of the system itself"""
        name = name or self._free_host_name("Infra")
        b = self.get_host_(name, "Part of the testing infrastructure")
        b.entity.host_type = HostType.ADMINISTRATIVE
        b.entity.external_activity = ExternalActivity.UNLIMITED
        b.entity.match_priority = 5
        return b

    def multicast(self, address: str, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP multicast target"""
        conf = ProtocolConfigurer.as_configurer(protocol)
        return conf.as_multicast_(address, self)

    def broadcast(self, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP broadcast target"""
        conf = ProtocolConfigurer.as_configurer(protocol)
        add = f"{IPAddresses.BROADCAST}" if conf.transport == Protocol.UDP else f"{HWAddresses.BROADCAST}"
        return self.multicast(add, conf)

    def data(self, names: List[str], personal=False, password=False) -> 'SensitiveDataBuilder':
        """Declare pieces of security-relevant data"""
        d = [SensitiveData(n, personal=personal, password=password) for n in names]
        return SensitiveDataBuilder(self, d)

    def online_resource(self, key: str, url: str) -> Self:
        """Document online resource"""
        self.system.online_resources[key] = url
        return self

    def visualize(self) -> 'VisualizerBuilder':
        return VisualizerBuilder(self.visualizer)

    def load(self) -> 'EvidenceLoader':
        el = EvidenceLoader(self)
        self.loaders.append(el)
        return el

    def claims(self, base_label="explain") -> 'ClaimSetBuilder':
        self.claimSet.base_label = base_label
        return self.claimSet

    def get_host_(self, name: str, description: str) -> 'HostBuilder':
        """Get or create a host"""
        hb = self.hosts_by_name.get(name)
        if hb is None:
            h = Host(self.system, name)
            h.description = description
            h.match_priority = 10
            hb = HostBuilder(h, self)
        return hb

    def _free_host_name(self, name_base: str) -> str:
        n = self.system.free_child_name(name_base)
        if n != name_base:
            # dirty hack, check all names match keys
            self.hosts_by_name = {h.entity.name: h for h in self.hosts_by_name.values()}
        return n

    def finish_(self):
        """Finish the model"""
        # We want to have a authenticator related to each authenticated service
        return
        # NOTE: Not ready to go into this level now...
        # auth_map = DataUsage.map_authenticators(self.system, {})
        # for hb in self.hosts_by_name.values():
        #     for sb in hb.service_builders.values():
        #         s = sb.entity
        #         if s not in auth_map and s.authentication:
        #             auth = PieceOfData(f"Auth-{s.name}")  # default authenticator
        #             auth.authenticator_for.append(s)
        #             hb.use_data(DataPieceBuilder(self, [auth]))
        #             # property to link from service to authentication
        #             exp = f"Authentication by {auth.name} (implicit)"
        #             prop_v = Properties.AUTHENTICATION_DATA.value(explanation=exp)
        #             prop_v[0].set(s.properties, prop_v[1])


# Host types
BROWSER = HostType.BROWSER

# Connection types
ADMINISTRATIVE = ConnectionType.ADMINISTRATIVE
ENCRYPTED = ConnectionType.ENCRYPTED
PLAINTEXT = ConnectionType.UNKNOWN


# External activity
BANNED = ExternalActivity.BANNED
PASSIVE = ExternalActivity.PASSIVE
OPEN = ExternalActivity.OPEN
UNLIMITED = ExternalActivity.UNLIMITED


class Builder(SystemBuilder):
    """Model builder and runner"""
    def __init__(self, name="Unnamed system"):
        super().__init__(name)
        parser = argparse.ArgumentParser()
        parser.add_argument("--read", "-r", action="append", help="Read tool output from batch directories")
        parser.add_argument("--help-tools", action="store_true", help="List tools read from batch")
        parser.add_argument("--def-loads", "-L", type=str, help="Comma-separated list of tools to load")
        parser.add_argument("--set-ip", action="append", help="Set DNS-name for entity, format 'name=ip, ...'")
        parser.add_argument("--output", "-o", help="Output format")
        parser.add_argument("--dhcp", action="store_true", help="Add default DHCP server handling")
        parser.add_argument("--dns", action="store_true", help="Add default DNS server handling")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)

        parser.add_argument("--http-server", type=int, help="Listen HTTP requests at port")
        parser.add_argument("--test-delay", type=int, help="HTTP request artificial test delay, ms")
        parser.add_argument("--no-auth-ok", action="store_true", help="Skip check for auth token in TCSFW_SERVER_API_KEY")

        parser.add_argument("--test-get", action="append", help="Test API GET, repeat for many")
        parser.add_argument("--test-post", nargs=2, help="Test API POST")

        parser.add_argument("--log-events", action="store_true", help="Log events")

        self.parser = parser
        self.args = parser.parse_args()
        logging.basicConfig(format='%(message)s', level=getattr(logging, self.args.log_level or 'INFO'))

    def run(self):
        """Model is ready, run the checks"""
        if self.args.dhcp:
            self.any().serve(DHCP)
        if self.args.dns:
            self.any().serve(DNS)

        self.finish_()

        registry = Registry(Inspector(self.system))
        cc = RequirementClaimMapper(self.system)

        log_events = self.args.log_events
        if log_events:
            # print event log
            registry.logging.event_logger = registry.logger

        for set_ip in self.args.set_ip or []:
            name, _, ips = set_ip.partition("=")
            h = self.system.get_entity(name) or self.system.get_endpoint(DNSName.name_or_ip(name))
            if not isinstance(h, Host) or not h.is_relevant():
                raise ValueError(f"No such host '{name}'")
            for ip in ips.split(","):
                self.system.learn_ip_address(h, IPAddress.new(ip))

        label_filter = LabelFilter(self.args.def_loads or "")
        batch_import = BatchImporter(registry, filter=label_filter)
        for in_file in self.args.read or []:
            batch_import.import_batch(pathlib.Path(in_file))

        if self.args.help_tools:
            # print help and exit
            for label, sl in sorted(batch_import.evidence.items()):
                sl_s = ", ".join(sorted(set([s.name for s in sl])))
                print(f"{label:<20} {sl_s}")
            return

        # product claims, then explicit loaders (if any)
        for sub in self.claimSet.finish_loaders():
            sub.load(registry, cc, filter=label_filter)
        for ln in self.loaders:
            for sub in ln.subs:
                sub.load(registry, cc, filter=label_filter)

        api = VisualizerAPI(registry, cc, self.visualizer)
        dump_report = True
        if self.args.test_post:
            res, data = self.args.test_post
            resp, _ = api.api_post(APIRequest(res), io.BytesIO(data))
            print(json.dumps(resp, indent=4))
            dump_report = False
        if self.args.test_get:
            for res in self.args.test_get:
                print(json.dumps(api.api_get(APIRequest.parse(res)), indent=4))
                dump_report = False

        out_form = self.args.output
        if out_form and out_form.startswith("coverage"):
            cmd, _, spec_id = out_form.partition(":")
            cmd = cmd[8:]
            report = CoverageReport(registry.logging, cc)
            spec = report.load_specification(spec_id)
            report.print_summary(sys.stdout, spec, cmd.strip("- "))
        elif out_form and out_form.startswith("latex"):
            cmd, _, spec_id = out_form.partition(":")
            cmd = cmd[5:]
            spec = CoverageReport.load_specification(spec_id)
            report = LaTeXGenerator(self.system, spec, cc)
            report.generate(sys.stdout, cmd.strip(" -"))
        elif dump_report or out_form:
            report = Report(registry)
            if out_form in {'text', '', None}:
                report.print_report(sys.stdout)
            elif out_form == 'table-csv':
                report.tabular(sys.stdout)
            elif out_form == 'table-latex':
                report.tabular(sys.stdout, latex=True)
            else:
                raise Exception(f"Unknown output format '{out_form}'")

        if self.args.http_server:
            server = HTTPServerRunner(api, port=self.args.http_server, no_auth_ok=self.args.no_auth_ok)
            server.component_delay = (self.args.test_delay or 0) / 1000
            server.run()

        # # artificial connections for testing after pcaps, so that HW <-> IP resolved
        # for cn in self.args.connection or []:
        #     t_parser.add_artificial_connection(cn)
        # elif self.args.uml:
        #     print(PlantUMLRenderer().render(t_parser.system))
        # else:
        #     print(t_parser.inspector.print_summary(self.args.log_level == 'DEBUG'))


ProtocolType = Union['ProtocolConfigurer', Type['ProtocolConfigurer']]
ServiceOrGroup = Union['ServiceBuilder', 'ServiceGroup']


class NodeBuilder(NodeInterface):
    def __init__(self, entity: Addressable, system: SystemBuilder):
        super().__init__(entity, system)
        self.parent: Optional[NodeBuilder] = None
        self.system = system
        self.sw: Dict[str, SoftwareBuilder] = {}
        system.system.originals.add(entity)

    def new_address_(self, address: AnyAddress) -> AnyAddress:
        old = self.system.entity_by_address.get(address)
        if old:
            raise Exception(f"Duplicate address {address}, reserved by: {old.entity.name}")
        self.entity.addresses.add(address)
        self.system.entity_by_address[address] = self
        return address

    def new_service_(self, name: str, port=-1):
        """Create new service here"""
        return Service(Service.make_name(name, port), self.entity)

    def name(self, name: str) -> Self:
        """Define entity name, names with dot (.) are assumed to be DNS domain names"""
        self.entity.name = name
        if DNSName.looks_like(name):
            self.dns(name)
        return self

    def dns(self, name: str) -> Self:
        """Define DNS name"""
        dn = DNSName(name)
        if dn in self.system.entity_by_address:
            raise Exception(f"Using name many times: {dn}")
        self.system.entity_by_address[dn] = self
        self.entity.addresses.add(dn)
        return self

    def describe(self, text: str) -> Self:
        """Describe the system by a few sentences."""
        self.entity.description = text
        return self

    def external_activity(self, value: ExternalActivity) -> Self:
        self.entity.set_external_activity(value)
        return self

    def get_software(self) -> Software:
        return self.software().sw

    def software(self, name: Optional[str] = None) -> 'SoftwareBuilder':
        if name is None:
            name = Software.default_name(self.entity)
        sb = self.sw.get(name)
        if sb is None:
            sb = SoftwareBuilder(self, name)
            self.sw[name] = sb
        return sb

    def visual(self) -> 'NodeVisualBuilder':
        """Create visual for the host"""
        p = self
        while p.parent:
            p = p.parent
        return NodeVisualBuilder(p)

    def __rshift__(self, target: ServiceOrGroup) -> 'ConnectionBuilder':
        if isinstance(target, ServiceGroup):
            c = None
            for t in target.services:
                c = t.connection_(self)
            return c
        else:
            return target.connection_(self)

    def __repr__(self):
        return self.entity.__repr__()


class ServiceBuilder(NodeBuilder):
    def __init__(self, host: 'HostBuilder', service: Service):
        super().__init__(service, host.system)
        self.configurer: Optional[ProtocolConfigurer] = None
        self.entity = service
        self.entity.match_priority = 10
        self.entity.external_activity = host.entity.external_activity
        self.parent = host
        self.source_fixer: Optional[Callable[['HostBuilder'], 'ServiceBuilder']] = None

    def type(self, value: ConnectionType) -> 'ServiceBuilder':
        """Configure connection type"""
        # FIXME: We should block defining plaintext connection as admin?
        self.entity.con_type = value
        return self

    def authenticated(self, flag: bool) -> Self:
        """Is this service authenticated?"""
        self.entity.authentication = flag
        return self

    def __truediv__(self, protocol: ProtocolType) -> 'ServiceGroup':
        """Pick or add the configured protocol to host"""
        s = self.parent / protocol
        return ServiceGroup([self, s])

    def connection_(self, source: 'NodeBuilder') -> 'ConnectionBuilder':
        s = source
        if self.source_fixer:
            assert isinstance(s, HostBuilder)
            s = self.source_fixer(s)
        for c in s.entity.get_parent_host().connections:
            if c.source == s.entity and c.target == self.entity:
                # referring existing connection
                return ConnectionBuilder(c, (s, self))
        c = Connection(s.entity, self.entity)
        c.status = Status.EXPECTED
        c.con_type = self.entity.con_type
        for e in [s.entity, self.entity]:
            e.status = Status.EXPECTED
        s.entity.get_parent_host().connections.append(c)
        self.entity.get_parent_host().connections.append(c)
        return ConnectionBuilder(c, (s, self))


class ServiceGroup:
    def __init__(self, services: List[ServiceBuilder]):
        assert len(services) > 0, "Empty list of services"
        self.services = services

    def __truediv__(self, other: ServiceOrGroup | ProtocolType) -> 'ServiceGroup':
        g = self.services.copy()
        if isinstance(other, ServiceGroup):
            g.extend(other.services)
        elif isinstance(other, ServiceBuilder):
            g.append(other)
        else:
            conf = ProtocolConfigurer.as_configurer(other)
            g.append(conf.get_service_(self.services[0].parent))
        return ServiceGroup(g)

    def __repr__(self):
        return " / ".join([f"{s.entity.name}" for s in self.services])


class HostBuilder(HostInterface, NodeBuilder):
    def __init__(self, entity: Host, system: SystemBuilder):
        super().__init__(entity, system)
        self.entity = entity
        system.system.children.append(entity)
        entity.status = Status.EXPECTED
        system.hosts_by_name[entity.name] = self
        if DNSName.looks_like(entity.name):
            self.name(entity.name)
        self.service_builders: Dict[Tuple[Protocol, int], ServiceBuilder] = {}

    def hw(self, address: str) -> 'HostBuilder':
        """Add HW address"""
        add = self.new_address_(HWAddress.new(address))
        return self

    def ip(self, address: str) -> 'HostBuilder':
        """Add IP address"""
        add = self.new_address_(IPAddress.new(address))
        return self

    def serve(self, *protocols: ProtocolType) -> Self:
        """Serve the configured protocol or protocols"""
        for p in protocols:
            self / p
        return self

    def __lshift__(self, multicast: ServiceBuilder) -> 'ConnectionBuilder':
        """Receive broadcast or multicast"""
        mc = multicast.entity
        assert mc.is_multicast(), "Can only receive multicast"
        # no service created, just connection from this to the multicast node
        c = self >> multicast
        c.logical_only()
        return c

    def cookies(self) -> 'CookieBuilder':
        """Configure cookies in a browser"""
        return CookieBuilder(self)

    def use_data(self, *data: 'SensitiveDataBuilder') -> Self:
        """This host uses some sensitive data"""
        usage = DataStorages.get_storages(self.entity, add=True)
        for db in data:
            for d in db.data:
                usage.sub_components.append(DataReference(usage, d))
        return self

    def __truediv__(self, protocol: ProtocolType) -> ServiceBuilder:
        """Pick or add the configured protocol"""
        conf = ProtocolConfigurer.as_configurer(protocol)
        return conf.get_service_(self)

    def ignore_name_requests(self, *name: str) -> Self:
        """Ignore DNS name requests for these names"""
        self.entity.ignore_name_requests.update([DNSName(n) for n in name])
        return self

    def set_property(self, *key: str):
        """Set a model property"""
        p = PropertyKey.create(key).persistent()
        self.entity.set_property(p.verdict())  # inconclusive
        return self


class SensitiveDataBuilder:
    def __init__(self, parent: SystemBuilder, data: List[SensitiveData]):
        self.parent = parent
        self.data = data
        # all sensitive data lives at least in system
        usage = DataStorages.get_storages(parent.system, add=True)
        for d in data:
            usage.sub_components.append(DataReference(usage, d))

    def used_by(self, *host: HostBuilder) -> Self:
        """This data used/stored in a host"""
        for h in host:
            h.use_data(self)
        return self

    def authorize(self, *service: ServiceBuilder) -> Self:
        """This data is used for service authentication"""
        for s in service:
            s.parent.use_data(self)
            for d in self.data:
                d.authenticator_for.append(s.entity)
                # property to link from service to authentication
                prop_v = Properties.AUTHENTICATION_DATA.value(explanation=d.name)
                prop_v[0].set(s.entity.properties, prop_v[1])
        return self


class ConnectionBuilder:
    def __init__(self, connection: Connection, ends: Tuple[NodeBuilder, ServiceBuilder]):
        self.connection = connection
        self.ends = ends
        self.ends[0].system.system.originals.add(connection)

    def logical_only(self) -> Self:
        """Only a logical link"""
        self.connection.con_type = ConnectionType.LOGICAL
        return self

    def __repr__(self):
        return self.connection.__repr__()


class SoftwareBuilder(SoftwareInterface):
    def __init__(self, parent: NodeBuilder, software_name: str):
        self.sw: Software = Software.get_software(parent.entity, software_name)
        if self.sw is None:
            self.sw = Software(parent.entity, software_name)
            parent.entity.add_component(self.sw)
        self.parent = parent

    def get_software(self, name: Optional[str] = None) -> Software:
        return self.sw

    def updates_from(self, source: Union[ConnectionBuilder, ServiceBuilder, HostBuilder]) -> Self:
        host = self.parent.entity

        cs = []
        if isinstance(source, HostBuilder):
            end = source.entity
            for c in host.get_connections():
                if c.source.get_parent_host() == end or c.target.get_parent_host() == end:
                    cs.append(c)
        else:
            raise NotImplementedError("Only support updates_by host implemented")
        if not cs:
            raise Exception(f"No connection between {self.parent} - {source}")
        if len(cs) != 1:
            raise Exception(f"Several possible connections between {self.parent} - {source}")
        self.sw.update_connections.extend(cs)
        return self

    def first_release(self, date: str) -> Self:
        """First release as YYYY-MM-DD"""
        self.sw.info.first_release = ReleaseInfo.parse_time(date)
        return self

    def supported_until(self, date: str) -> Self:
        """Support end time YYYY-MM-DD"""
        # FIXME EndOfSupport(ReleaseInfo.parse_time(date))
        return self

    def update_frequency(self, days: float) -> Self:
        """Target update frequency, days"""
        self.sw.info.interval_days = days
        return self


class NodeVisualBuilder:
    """Visual builder for an node"""
    def __init__(self, entity: NodeBuilder):
        self.entity = entity
        self.image_url: Optional[str] = None
        self.image_scale: int = 100

    def hide(self) -> Self:
        self.entity.entity.visual = False
        return self

    def image(self, url: str, scale=100) -> Self:
        self.image_url = url
        self.image_scale = scale
        return self


class VisualizerBuilder:
    """Visual builder"""
    def __init__(self, visualizer: Visualizer):
        self.visualizer = visualizer

    def place(self, *places: str) -> Self:
        self.visualizer.placement = places
        return self

    def where(self, handles: Dict[str, Union[NodeBuilder, NodeVisualBuilder]]) -> Self:
        for h, b in handles.items():
            if isinstance(b, NodeVisualBuilder):
                ent = b.entity.entity.get_parent_host()
                if b.image_url:
                    self.visualizer.images[ent] = b.image_url, b.image_scale
            else:
                ent = b.entity.get_parent_host()
            self.visualizer.handles[h] = ent
        return self


class ProtocolConfigurer:
    """Protocol configurer"""
    def __init__(self, transport: Optional[Protocol] = None, protocol: Protocol = Protocol.ANY, name="", port=-1,
                 group: List['ProtocolConfigurer'] = None):
        self.transport = transport
        self.protocol = protocol
        self.service_name = name
        self.port_to_name = True
        self.service_port = port
        self.host_type = HostType.GENERIC
        self.con_type = ConnectionType.UNKNOWN
        self.authentication = False
        self.external_activity: Optional[ExternalActivity.BANNED] = None
        self.critical_parameter: List[SensitiveData] = []

    def name(self, value: str) -> Self:
        """Name the service"""
        self.service_name = value
        return self

    def set_type(self, value: ConnectionType) -> Self:
        """Claim encrypted service"""
        self.con_type = value
        return self

    def __repr__(self):
        return f"{self.service_name}"

    def get_service_(self, parent: HostBuilder) -> ServiceBuilder:
        """Create or get service builder"""
        old = parent.service_builders.get((self.transport, self.service_port if self.port_to_name else -1))
        if old:
            return old
        b = self._create_service(parent)
        parent.service_builders[(self.transport, self.service_port)] = b
        b.entity.status = Status.EXPECTED
        assert b.entity.parent == parent.entity
        parent.entity.children.append(b.entity)
        if not b.entity.addresses:
            # E.g. DHCP service fills this oneself
            b.entity.addresses.add(EndpointAddress(Addresses.ANY, self.transport, self.service_port))
        if self.critical_parameter:
            parent.use_data(SensitiveDataBuilder(parent.system, self.critical_parameter))  # critical protocol parameters
        return b

    def _create_service(self, parent: HostBuilder) -> ServiceBuilder:
        s = ServiceBuilder(parent,
                           parent.new_service_(self.service_name, self.service_port if self.port_to_name else -1))
        s.configurer = self
        s.entity.authentication = self.authentication
        s.entity.host_type = self.host_type
        s.entity.con_type = self.con_type
        if self.external_activity is not None:
            s.entity.external_activity = self.external_activity
        s.entity.protocol = self.protocol
        return s

    def as_multicast_(self, address: str, system: SystemBuilder) -> ServiceBuilder:
        """The protocol as multicast"""
        raise NotImplementedError(f"{self.service_name} cannot be broad/multicast")

    @classmethod
    def as_configurer(cls, protocol: ProtocolType):
        if isinstance(protocol, ProtocolConfigurer):
            return protocol
        i = protocol()
        assert isinstance(i, ProtocolConfigurer), f"Not protocol type: {protocol.__name__}"
        return i


class ARP(ProtocolConfigurer):
    def __init__(self):
        super().__init__(Protocol.ARP, name="ARP")
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        # ARP make requests and replies
        self.external_activity = ExternalActivity.UNLIMITED

    def get_service_(self, parent: HostBuilder) -> ServiceBuilder:
        host_s = super().get_service_(parent)
        # ARP can be broadcast, get or create the broadcast host and service
        bc_node = parent.system.get_host_(f"{HWAddresses.BROADCAST}", description="Broadcast")
        bc_s = bc_node.service_builders.get((self.transport, self.service_port))
        # Three entities:
        # host_s: ARP service at host
        # bc_node: Broadcast logical node
        # bc_s: ARP service a the broadcast node
        if not bc_s:
            # create ARP service
            bc_node.new_address_(HWAddresses.BROADCAST)
            bc_node.entity.external_activity = ExternalActivity.OPEN   # anyone can make broadcasts (it does not reply)
            bc_node.entity.host_type = HostType.ADMINISTRATIVE
            bc_s = bc_node / ProtocolConfigurer(transport=Protocol.ARP, name="ARP")
            bc_s.entity.host_type = HostType.ADMINISTRATIVE
            bc_s.entity.con_type = ConnectionType.ADMINISTRATIVE
            bc_s.entity.external_activity = bc_node.entity.external_activity
            host_s.entity.external_activity = self.external_activity
        c_ok = any([c.source == host_s.entity for c in host_s.entity.get_parent_host().connections])
        if not c_ok:
            host_s >> bc_s
        return bc_s  # NOTE: the broadcast


class DHCP(ProtocolConfigurer):
    def __init__(self, port=67):
        super().__init__(Protocol.UDP, port=port, name="DHCP")
        # DHCP requests go to broadcast, thus the reply looks like request
        self.external_activity = ExternalActivity.UNLIMITED

    def _create_service(self, parent: HostBuilder) -> ServiceBuilder:
        host_s = ServiceBuilder(parent, DHCPService(parent.entity))
        host_s.entity.external_activity = self.external_activity

        def create_source(host: HostBuilder):
            # DHCP client uses specific port 68 for requests
            src = UDP(port=68, name="DHCP")
            src.port_to_name = False
            cs = host / src
            cs.entity.host_type = HostType.ADMINISTRATIVE
            cs.entity.con_type = ConnectionType.ADMINISTRATIVE
            cs.entity.client_side = True
            return cs
        host_s.source_fixer = create_source
        return host_s


class DNS(ProtocolConfigurer):
    def __init__(self, port=53, captive=False):
        super().__init__(Protocol.UDP, port=port, name="DNS")
        self.external_activity = ExternalActivity.OPEN
        self.captive_portal = captive

    def _create_service(self, parent: HostBuilder) -> ServiceBuilder:
        dns_s = DNSService(parent.entity)
        dns_s.captive_portal = self.captive_portal
        s = ServiceBuilder(parent, dns_s)
        s.entity.external_activity = self.external_activity
        return s


class EAPOL(ProtocolConfigurer):
    def __init__(self):
        super().__init__(Protocol.ETHERNET, port=0x888e, name="EAPOL")
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False


class HTTP(ProtocolConfigurer):
    def __init__(self, port=80, auth: Optional[bool] = None):
        super().__init__(Protocol.TCP, port=port, protocol=Protocol.HTTP, name="HTTP")
        if auth is not None:
            self.authentication = auth
        self.redirect_only = False

    def redirect(self) -> Self:
        """This is only HTTP redirect to TLS"""
        self.redirect_only = True
        return self

    def get_service_(self, parent: HostBuilder) -> ServiceBuilder:
        s = super().get_service_(parent)
        if self.redirect_only:
            # persistent property
            s.entity.set_property(Properties.HTTP_REDIRECT.verdict(explanation="HTTP redirect to TLS"))
        return s


class ICMP(ProtocolConfigurer):
    def __init__(self):
        super().__init__(Protocol.IP, port=1, name="ICMP")
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False

    def _create_service(self, parent: HostBuilder) -> ServiceBuilder:
        s = super()._create_service(parent)
        s.entity.name = "ICMP"  # a bit of hack...
        s.entity.host_type = HostType.ADMINISTRATIVE
        s.entity.con_type = ConnectionType.ADMINISTRATIVE
        # ICMP can be a service for other hosts
        s.entity.external_activity = max(self.external_activity, parent.entity.external_activity)
        return s


class IP(ProtocolConfigurer):
    def __init__(self, administration=False):
        super().__init__(Protocol.IP, name="IP")
        if administration:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class TLS(ProtocolConfigurer):
    def __init__(self, port=443, auth: Optional[bool] = None):
        super().__init__(Protocol.TCP, port=port, protocol=Protocol.TLS, name="TLS")
        if auth is not None:
            self.authentication = auth
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("TLS-creds"))


class NTP(ProtocolConfigurer):
    def __init__(self, port=123):
        super().__init__(Protocol.UDP, port=port, name="NTP")
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN


class SSH(ProtocolConfigurer):
    def __init__(self, port=22):
        super().__init__(Protocol.TCP, port=port, protocol=Protocol.SSH, name="SSH")
        self.authentication = True
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("SSH-creds"))


class TCP(ProtocolConfigurer):
    def __init__(self, port: int, name="TCP", administrative=False):
        super().__init__(Protocol.TCP, port=port, name=name)
        if administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class UDP(ProtocolConfigurer):
    def __init__(self, port: int, name="UDP", administrative=False):
        super().__init__(Protocol.UDP, port=port, name=name)
        if administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE

    def as_multicast_(self, address: str, system: SystemBuilder) -> 'ServiceBuilder':
        b = system.get_host_(address, description="Multicast")
        # Explicitly configured multicast nodes, at least are not administrative
        # b.entity.host_type = HostType.ADMINISTRATIVE
        addr = IPAddress.new(address)
        if addr not in b.entity.addresses:
            b.new_address_(addr)
        return self.get_service_(b)


class BLEAdvertisement(ProtocolConfigurer):
    def __init__(self, event_type: int):
        super().__init__(Protocol.BLE, port=event_type, name="BLE Ad", protocol=Protocol.BLE)

    def as_multicast_(self, address: str, system: SystemBuilder) -> 'ServiceBuilder':
        b = system.get_host_(name="BLE Ads", description="Bluetooth LE Advertisements")
        b.new_address_(Addresses.BLE_Ad)
        b.entity.external_activity = ExternalActivity.PASSIVE
        return self.get_service_(b)


class ClaimBuilder:
    """Claim builder"""
    def __init__(self, builder: 'ClaimSetBuilder', explanation: str, verdict: Verdict, label: str,
                 authority=ClaimAuthority.MODEL):
        self.builder = builder
        self.authority = authority
        self.source = builder.sources.get(label)
        if self.source is None:
            builder.sources[label] = self.source = EvidenceSource(f"Claims '{label}'", label=label)
        self._explanation = explanation
        self._keys: List[PropertyKey] = []
        self._locations: List[Entity] = []
        self._verdict = verdict
        builder.claim_builders.append(self)

    def key(self, *segments: str) -> Self:
        """Add key to touch"""
        key = PropertyKey.create(segments)
        if key.is_protected():
            key = key.prefix_key(Properties.PREFIX_MANUAL)
        self._keys.append(key)
        return self

    def keys(self, *key: Tuple[str, ...]) -> Self:
        """Add keys to touch"""
        for seg in key:
            assert isinstance(seg, tuple), f"Bad key {seg}"
            k = PropertyKey.create(seg)
            if k.is_protected():
                k = k.prefix_key(Properties.PREFIX_MANUAL)
            self._keys.append(k)
        return self

    def verdict_ignore(self) -> Self:
        """Override verdict to ignore"""
        self._verdict = Verdict.IGNORE
        return self

    def verdict_pass(self) -> Self:
        """Override verdict to pass"""
        self._verdict = Verdict.PASS
        return self

    def at(self, *locations: Union[SystemBuilder, NodeBuilder, ConnectionBuilder]) -> 'Self':
        """Set claimed location(s)"""
        for lo in locations:
            if isinstance(lo, SystemBuilder):
                loc = lo.system
            elif isinstance(lo, NodeBuilder):
                loc = lo.entity
            else:
                loc = lo.connection
            self._locations.append(loc)
        return self

    def software(self, *locations: NodeBuilder) -> 'Self':
        """Claims for software in the locations"""
        for lo in locations:
            for sw in Software.list_software(lo.entity):
                self._locations.append(sw)
        return self

    def claims(self, *claims: Union[Claim, Tuple[str, str]]) -> Self:
        """Add extended claims"""
        # bug? - requirements may be placed in extra tuple?
        cl = []
        for c in claims:
            if isinstance(c, tuple) and isinstance(c[0], Claim):
                cl.extend(c)
            else:
                cl.append(c)
        # self._claims.extend(cl)
        return self

    def vulnerabilities(self, *entry: Tuple[str, str]) -> Self:
        """Explain CVE-entries"""
        for com, cve in entry:
            self._keys.append(PropertyKey("vulnz", com, cve.lower()))
        return self

    def finish_loaders(self) -> SubLoader:
        """Finish by returning the loader to use"""
        this = self
        locations = self._locations
        keys = self._keys

        class ClaimLoader(SubLoader):
            def __init__(self):
                super().__init__("Manual checks")
                self.source_label = this.source.label

            def load(self, registry: Registry, coverage: RequirementClaimMapper, filter: LabelFilter):
                if not filter.filter(self.source_label):
                    return
                evidence = Evidence(this.source)
                for loc in locations:
                    for key in keys:
                        kv = PropertyKey.create(key.segments).verdict(this._verdict, explanation=this._explanation)
                        ev = PropertyEvent(evidence, loc, kv)
                        registry.property_update(ev)
        return ClaimLoader()


class ClaimSetBuilder(BuilderInterface):
    """Builder for set of claims"""
    def __init__(self, builder: SystemBuilder):
        self.builder = builder
        self.claim_builders: List[ClaimBuilder] = []
        self.tool_plans: List[ToolPlanLoader] = []
        self.base_label = "explain"
        self.sources: Dict[str, EvidenceSource] = {}

    def claim(self, explanation: str, verdict=Verdict.PASS) -> ClaimBuilder:
        """Self-made claims"""
        return ClaimBuilder(self, explanation, verdict, self.base_label)

    def reviewed(self, explanation="", verdict=Verdict.PASS) -> ClaimBuilder:
        """Make reviewed claims"""
        return ClaimBuilder(self, explanation, verdict, self.base_label, ClaimAuthority.MANUAL)

    def ignore(self, explanation="") -> ClaimBuilder:
        """Ignore claims or requirements"""
        return ClaimBuilder(self, explanation, Verdict.IGNORE, self.base_label)

    def plan_tool(self, tool_name: str, group: Tuple[str, str], location: RequirementSelector, 
                  *key: Tuple[str, ...]) -> ToolPlanLoader:
        """Plan use of a tool using the property keys it is supposed to set"""
        sl = ToolPlanLoader(group)
        sl.location = location
        for k in key:
            pk = PropertyKey.create(k)
            pv = pk.verdict(Verdict.PASS, explanation=f"{tool_name} sets {pk}")
            sl.properties[pk] = pv[1]
        self.tool_plans.append(sl)
        return sl

    def set_base_label(self, base_label: str) -> Self:
        """Set label for the claims"""
        self.base_label = base_label
        return self

    def finish_loaders(self) -> List[SubLoader]:
        """Finish"""
        ls = []
        ls.extend([cb.finish_loaders() for cb in self.claim_builders])
        ls.extend(self.tool_plans)
        return ls


class CookieBuilder(BuilderInterface):
    """Cookies in a browser"""
    def __init__(self, builder: HostBuilder):
        self.builder = builder
        self.component = Cookies.cookies_for(builder.entity)

    def set(self, cookies: Dict[str, Tuple[str, str, str]]):
        """Set cookies, name: domain, path, explanation"""
        for name, p in cookies.items():
            self.component.cookies[name] = CookieData(p[0], p[1], p[2])

if __name__ == "__main__":
    Builder().run()
