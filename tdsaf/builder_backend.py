"""Model builder backend"""

import argparse
import io
import ipaddress
import json
import logging
import pathlib
import shutil
import sys
from typing import Any, Callable, Dict, List, Optional, Self, Tuple, Union

from tdsaf.common.address import (AddressAtNetwork, Addresses, AnyAddress, DNSName, EndpointAddress, EntityTag,
                                  HWAddress, HWAddresses, IPAddress, IPAddresses, Network, Protocol)
from tdsaf.common.basics import ConnectionType, ExternalActivity, HostType, Status
from tdsaf.adapters.batch_import import BatchImporter, LabelFilter
from tdsaf.client_api import APIRequest
from tdsaf.core.components import CookieData, Cookies, DataReference, StoredData, OperatingSystem, Software
from tdsaf.common.entity import ClaimAuthority, Entity
from tdsaf.core.event_interface import PropertyEvent
from tdsaf.common.release_info import ReleaseInfo
from tdsaf.http_server import HTTPServerRunner
from tdsaf.main import (ARP, DHCP, DNS, EAPOL, ICMP, NTP, SSH, HTTP, TCP, UDP, IP, TLS,
                        BLEAdvertisement, ClaimBuilder, ClaimSetBuilder, ConnectionBuilder,
                        CookieBuilder, HostBuilder, NetworkBuilder, NodeBuilder, NodeVisualBuilder,
                        ConfigurationException, OSBuilder, ProtocolConfigurer, ProtocolType,
                        SensitiveDataBuilder, ServiceBuilder, ServiceGroupBuilder, ServiceOrGroup,
                        SoftwareBuilder, SystemBuilder, VisualizerBuilder)
from tdsaf.core.main_tools import EvidenceLoader, NodeManipulator, SubLoader, ToolPlanLoader
from tdsaf.core.model import Addressable, Connection, Host, IoTSystem, SensitiveData, Service
from tdsaf.common.property import Properties, PropertyKey
from tdsaf.core.registry import Registry
from tdsaf.core.inspector import Inspector
from tdsaf.core.result import Report
from tdsaf.core.selector import AbstractSelector
from tdsaf.core.services import DHCPService, DNSService
from tdsaf.core.sql_database import SQLDatabase
from tdsaf.common.traffic import Evidence, EvidenceSource
from tdsaf.common.verdict import Verdict
from tdsaf.visualizer import Visualizer, VisualizerAPI


class SystemBackend(SystemBuilder):
    """System model builder"""

    def __init__(self, name="Unnamed system"):
        self.system = IoTSystem(name)
        self.hosts_by_name: Dict[str, 'HostBackend'] = {}
        self.entity_by_address: Dict[AddressAtNetwork, 'NodeBackend'] = {}
        self.claim_set = ClaimSetBackend(self)
        self.attachments: List[pathlib.Path] = []
        self.visualizer = Visualizer()
        self.loaders: List[EvidenceLoader] = []
        self.protocols: Dict[Any, 'ProtocolBackend'] = {}

    def network(self, subnet="", ip_mask: Optional[str] = None) -> 'NetworkBuilder':
        if subnet:
            nb = NetworkBackend(self, subnet)
        else:
            nb = NetworkBackend(self)
        if ip_mask:
            nb.mask(ip_mask)
        return nb

    def device(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Device")
        b = self.get_host_(name, "Internet Of Things device")
        b.entity.host_type = HostType.DEVICE
        return b

    def backend(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Backend")
        b = self.get_host_(name, "Backend service over Internet")
        b.entity.host_type = HostType.REMOTE
        b.entity.external_activity = ExternalActivity.OPEN
        return b

    def mobile(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Mobile")
        b = self.get_host_(name, "Mobile application")
        b.entity.host_type = HostType.MOBILE
        # who know what apps etc.
        b.entity.external_activity = ExternalActivity.UNLIMITED
        return b

    def browser(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Browser")
        b = self.get_host_(name, "Browser")
        b.entity.host_type = HostType.BROWSER
        return b

    def any(self, name="", node_type: HostType = None) -> 'HostBackend':
        name = name or self._free_host_name("Host")
        b = self.get_host_(name, "Any host")
        b.entity.any_host = True
        b.entity.host_type = HostType.ADMINISTRATIVE if node_type is None else node_type
        # might serve other network nodes
        b.entity.external_activity = ExternalActivity.UNLIMITED
        return b

    def infra(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Infra")
        b = self.get_host_(name, "Part of the testing infrastructure")
        b.entity.host_type = HostType.ADMINISTRATIVE
        b.entity.external_activity = ExternalActivity.UNLIMITED
        b.entity.match_priority = 5
        return b

    def multicast(self, address: str, protocol: 'ProtocolConfigurer') -> 'ServiceBackend':
        conf = self.get_protocol_backend(protocol)
        return conf.as_multicast_(address, self)

    def broadcast(self, protocol: 'ProtocolConfigurer') -> 'ServiceBackend':
        conf = self.get_protocol_backend(protocol)
        add = f"{IPAddresses.BROADCAST}" if conf.transport == Protocol.UDP \
            else f"{HWAddresses.BROADCAST}"
        return self.multicast(add, protocol)

    def data(self, names: List[str], personal=False, password=False) -> 'SensitiveDataBackend':
        d = [SensitiveData(n, personal=personal, password=password)
             for n in names]
        return SensitiveDataBackend(self, d)

    def online_resource(self, key: str, url: str) -> Self:
        self.system.online_resources[key] = url
        return self

    def attach_file(self, file_path: str, relative_to: Optional[str] = None) -> Self:
        if relative_to:
            rel_to = pathlib.Path(relative_to)
            if not rel_to.is_dir():
                rel_to = rel_to.parent
            p = rel_to / file_path
        else:
            p = pathlib.Path(file_path)
        assert p.exists(), f"File not found: {p}"
        self.attachments.append(p.absolute())
        return self

    def visualize(self) -> 'VisualizerBackend':
        return VisualizerBackend(self.visualizer)

    def load(self) -> 'EvidenceLoader':
        el = EvidenceLoader(self)
        self.loaders.append(el)
        return el

    def claims(self, base_label="explain") -> 'ClaimSetBackend':
        self.claim_set.base_label = base_label
        return self.claim_set

    # Backend methods

    def get_host_(self, name: str, description: str) -> 'HostBackend':
        """Get or create a host"""
        hb = self.hosts_by_name.get(name)
        if hb is None:
            h = Host(self.system, name, tag=EntityTag.new(name))  # tag is not renamed, name can be
            h.description = description
            h.match_priority = 10
            hb = HostBackend(h, self)
        return hb

    def get_protocol_backend(self,
                             protocol: 'ProtocolConfigurer' | ProtocolType) -> 'ProtocolBackend':
        """Get protocol backend, create if required"""
        be = self.protocols.get(protocol)
        if be is None:
            if isinstance(protocol, ProtocolConfigurer):
                p = protocol
            else:
                p = protocol()
            assert isinstance(
                p, ProtocolConfigurer), f"Not protocol type: {p.__class__.__name__}"
            be = self.protocols[p] = ProtocolBackend.new(p)
        return be

    def _free_host_name(self, name_base: str) -> str:
        n = self.system.free_child_name(name_base)
        if n != name_base:
            # dirty hack, check all names match keys
            self.hosts_by_name = {
                h.entity.name: h for h in self.hosts_by_name.values()}
        return n

    def finish_(self):
        """Finish the model"""
        # each real host must have software
        for h in self.system.get_hosts():
            if not h.any_host and h.host_type != HostType.BROWSER:
                Software.ensure_default_software(h)

        # We want to have a authenticator related to each authenticated service
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


class NodeBackend(NodeBuilder, NodeManipulator):
    """Node building backend"""

    def __init__(self, entity: Addressable, system: SystemBackend):
        super().__init__(system)
        self.system = system
        self.entity = entity
        self.parent: Optional[NodeBackend] = None
        self.sw: Dict[str, SoftwareBackend] = {}
        system.system.originals.add(entity)

    def name(self, name: str) -> Self:
        self.entity.name = name
        if DNSName.looks_like(name):
            self.dns(name)
        return self

    def dns(self, name: str) -> Self:
        dn = DNSName(name)
        networks = self.entity.get_networks_for(dn)
        assert len(networks) == 1, "DNS name must be in one network"
        self.entity.addresses.add(dn)
        key = AddressAtNetwork(dn, networks[0])
        if key in self.system.entity_by_address:
            raise ConfigurationException(f"Using name many times: {dn}")
        self.system.entity_by_address[key] = self
        return self

    def describe(self, text: str) -> Self:
        """Describe the system by a few sentences."""
        self.entity.description = text
        return self

    def external_activity(self, value: ExternalActivity) -> Self:
        self.entity.set_external_activity(value)
        return self

    def in_networks(self, *network: NetworkBuilder) -> Self:
        if any(a.get_ip_address() for a in self.entity.addresses):
            raise ConfigurationException(f"Cannot set network after IP addresses for {self.entity.name}")
        self.entity.networks = [n.network for n in network]
        return self

    def software(self, name: Optional[str] = None) -> 'SoftwareBackend':
        if name is None:
            name = Software.default_name(self.entity)
        sb = self.sw.get(name)
        if sb is None:
            sb = SoftwareBackend(self, name)
            self.sw[name] = sb
        return sb

    def visual(self) -> 'NodeVisualBackend':
        p = self
        while p.parent:
            p = p.parent
        return NodeVisualBackend(p)

    def __rshift__(self, target: ServiceOrGroup) -> 'ConnectionBackend':
        if isinstance(target, ServiceGroupBackend):
            c = None
            for t in target.services:
                c = t.connection_(self)
            return c
        return target.connection_(self)

    # Backend methods

    def get_node(self) -> NodeBuilder:
        return self.entity

    def new_address_(self, address: AnyAddress) -> AnyAddress:
        """Add new address to the entity"""
        networks = self.entity.get_networks_for(address)
        if not networks:
            raise ConfigurationException(f"Address {address} not in any network range of {self.entity.name}")
        self.entity.addresses.add(address)
        for nw in networks:
            key = AddressAtNetwork(address, nw)
            old = self.system.entity_by_address.get(key)
            if old:
                raise ConfigurationException(
                    f"Duplicate address {address}, reserved by: {old.entity.name}")
            self.system.entity_by_address[key] = self
        return address

    def new_service_(self, name: str, port=-1):
        """Create new service here"""
        return Service(Service.make_name(name, port), self.entity)

    def get_software(self) -> Software:
        """Get the software entity"""
        return self.software().sw

    def __repr__(self):
        return self.entity.__repr__()


class ServiceBackend(NodeBackend, ServiceBuilder):
    """Service builder backend"""

    def __init__(self, host: 'HostBackend', service: Service):
        NodeBackend.__init__(self, service, host.system)
        ServiceBuilder.__init__(self, host.system)
        self.entity = service
        self.configurer: Optional[ProtocolConfigurer] = None
        self.entity.match_priority = 10
        self.entity.external_activity = host.entity.external_activity
        self.parent = host
        self.source_fixer: Optional[Callable[[
            'HostBackend'], 'ServiceBackend']] = None

    def type(self, value: ConnectionType) -> 'ServiceBackend':
        self.entity.con_type = value
        return self

    def authenticated(self, flag: bool) -> Self:
        self.entity.authentication = flag
        return self

    def __truediv__(self, protocol: ProtocolType) -> 'ServiceGroupBackend':
        s = self.parent / protocol
        return ServiceGroupBackend([self, s])

    # Backend methods

    def connection_(self, source: 'NodeBackend') -> 'ConnectionBackend':
        """Create connection from source to this service"""
        s = source
        if self.source_fixer:
            assert isinstance(s, HostBackend)
            s = self.source_fixer(s)
        for c in s.entity.get_parent_host().connections:
            if c.source == s.entity and c.target == self.entity:
                # referring existing connection
                return ConnectionBackend(c, (s, self))
        c = Connection(s.entity, self.entity)
        c.status = Status.EXPECTED
        c.con_type = self.entity.con_type
        for e in [s.entity, self.entity]:
            e.status = Status.EXPECTED
        s.entity.get_parent_host().connections.append(c)
        self.entity.get_parent_host().connections.append(c)
        return ConnectionBackend(c, (s, self))


class ServiceGroupBackend(ServiceGroupBuilder):
    """Service group builder backend"""

    def __init__(self, services: List[ServiceBackend]):
        assert len(services) > 0, "Empty list of services"
        self.services = services

    def __truediv__(self, other: ServiceOrGroup | ProtocolType) -> 'ServiceGroupBackend':
        g = self.services.copy()
        if isinstance(other, ServiceGroupBackend):
            g.extend(other.services)
        elif isinstance(other, ServiceBackend):
            g.append(other)
        else:
            system = self.services[0].system
            conf = system.get_protocol_backend(other)
            g.append(conf.get_service_(self.services[0].parent))
        return ServiceGroupBackend(g)

    # Backend methods

    def __repr__(self):
        return " / ".join([f"{s.entity.name}" for s in self.services])


class HostBackend(NodeBackend, HostBuilder):
    """Host builder backend"""

    def __init__(self, entity: Host, system: SystemBackend):
        NodeBackend.__init__(self, entity, system)
        HostBuilder.__init__(self, system)
        self.entity = entity
        system.system.children.append(entity)
        entity.status = Status.EXPECTED
        system.hosts_by_name[entity.name] = self
        if DNSName.looks_like(entity.name):
            self.name(entity.name)
        self.service_builders: Dict[Tuple[Protocol, int], ServiceBackend] = {}

    def hw(self, address: str) -> 'HostBackend':
        self.new_address_(HWAddress.new(address))
        return self

    def ip(self, address: str) -> 'HostBackend':
        self.new_address_(IPAddress.new(address))
        return self

    def serve(self, *protocols: ProtocolType) -> Self:
        for p in protocols:
            self / p  # pylint: disable=pointless-statement
        return self

    def os(self) -> OSBuilder:
        return OSBackend(self)

    def __lshift__(self, multicast: ServiceBackend) -> 'ConnectionBackend':
        mc = multicast.entity
        assert mc.is_multicast(), "Can only receive multicast"
        # no service created, just connection from this to the multicast node
        c = self >> multicast
        c.logical_only()
        return c

    def cookies(self) -> 'CookieBackend':
        return CookieBackend(self)

    def use_data(self, *data: 'SensitiveDataBackend') -> Self:
        for db in data:
            db.used_by(hosts=[self])
        return self

    def __truediv__(self, protocol: ProtocolType) -> ServiceBackend:
        conf = self.system.get_protocol_backend(protocol)
        return conf.get_service_(self)

    def ignore_name_requests(self, *name: str) -> Self:
        self.entity.ignore_name_requests.update([DNSName(n) for n in name])
        return self

    def set_property(self, *key: str):
        p = PropertyKey.create(key).persistent()
        self.entity.set_property(p.verdict())  # inconclusive
        return self


class SensitiveDataBackend(SensitiveDataBuilder):
    """Sensitive data builder backend"""

    def __init__(self, parent: SystemBackend, data: List[SensitiveData]):
        super().__init__(parent)
        self.parent = parent
        self.data = data
        # all sensitive data lives at least in system
        usage = StoredData.get_data(parent.system)
        for d in data:
            usage.sub_components.append(DataReference(parent.system, d))
        self.default_location = True

    def used_by(self, hosts: List[HostBuilder]) -> Self:
        if self.default_location:
            # default location is overriden
            self.default_location = False
            StoredData.get_data(self.parent.system).sub_components = []
        for h in hosts:
            storage = StoredData.get_data(h.entity)
            for d in self.data:
                storage.sub_components.append(DataReference(h.entity, d))
        return self


class ConnectionBackend(ConnectionBuilder):
    """Connection builder backendq"""

    def __init__(self, connection: Connection, ends: Tuple[NodeBackend, ServiceBackend]):
        self.connection = connection
        self.ends = ends
        self.ends[0].system.system.originals.add(connection)

    def logical_only(self) -> Self:
        self.connection.con_type = ConnectionType.LOGICAL
        return self

    def __repr__(self):
        return self.connection.__repr__()


class NetworkBackend(NetworkBuilder):
    """Network or subnet backend"""
    def __init__(self, parent: SystemBackend, name=""):
        super().__init__(Network(name) if name else parent.system.get_default_network())
        self.parent = parent
        self.name = name

    def mask(self, mask: str) -> Self:
        self.network.ip_network = ipaddress.ip_network(mask)
        return self

    def __repr__(self) -> str:
        return self.name


class SoftwareBackend(SoftwareBuilder):
    """Software builder backend"""

    def __init__(self, parent: NodeBackend, software_name: str):
        self.sw: Software = Software.get_software(parent.entity, software_name)
        if self.sw is None:
            self.sw = Software(parent.entity, software_name)
            parent.entity.add_component(self.sw)
        self.parent = parent

    def updates_from(self, source: Union[ConnectionBackend, ServiceBackend, HostBackend]) -> Self:
        host = self.parent.entity

        cs = []
        if isinstance(source, HostBackend):
            end = source.entity
            for c in host.get_connections():
                if c.source.get_parent_host() == end or c.target.get_parent_host() == end:
                    cs.append(c)
        else:
            raise ConfigurationException(
                "Only support updates_by host implemented")
        if not cs:
            raise ConfigurationException(f"No connection between {self.parent} - {source}")
        if len(cs) != 1:
            raise ConfigurationException(
                f"Several possible connections between {self.parent} - {source}")
        self.sw.update_connections.extend(cs)
        return self

    def first_release(self, date: str) -> Self:
        """First release as YYYY-MM-DD"""
        self.sw.info.first_release = ReleaseInfo.parse_time(date)
        return self

    def supported_until(self, date: str) -> Self:
        """Support end time YYYY-MM-DD"""
        # EndOfSupport(ReleaseInfo.parse_time(date)) - not implemented
        return self

    def update_frequency(self, days: float) -> Self:
        """Target update frequency, days"""
        self.sw.info.interval_days = days
        return self

    # Backend methods

    def get_software(self, _name: Optional[str] = None) -> Software:
        """Get the software entity"""
        return self.sw


class CookieBackend(CookieBuilder):
    """Cookie builder backend"""

    def __init__(self, builder: HostBackend):
        self.builder = builder
        self.component = Cookies.cookies_for(builder.entity)

    def set(self, cookies: Dict[str, Tuple[str, str, str]]):
        for name, p in cookies.items():
            self.component.cookies[name] = CookieData(p[0], p[1], p[2])


class NodeVisualBackend(NodeVisualBuilder):
    """Node visual builder backend"""

    def __init__(self, entity: NodeBackend):
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


class VisualizerBackend(VisualizerBuilder):
    """Visual builder backend"""

    def __init__(self, visualizer: Visualizer):
        self.visualizer = visualizer

    def place(self, *places: str) -> Self:
        self.visualizer.placement = places
        return self

    def where(self, handles: Dict[str, Union[NodeBackend, NodeVisualBackend]]) -> Self:
        for h, b in handles.items():
            if isinstance(b, NodeVisualBackend):
                ent = b.entity.entity.get_parent_host()
                if b.image_url:
                    self.visualizer.images[ent] = b.image_url, b.image_scale
            else:
                ent = b.entity.get_parent_host()
            self.visualizer.handles[h] = ent
        return self


class ProtocolBackend:
    """Protocol configurer backend"""
    @classmethod
    def new(cls, configurer: ProtocolConfigurer) -> 'ProtocolBackend':
        """New backend for the configurer"""
        pt = configurer.__class__
        pt_cre = ProtocolConfigurers.Constructors.get(pt)
        if pt_cre is None:
            raise ValueError(f"No backend mapped for {pt}")
        be = pt_cre(configurer)
        be.networks = [n.network for n in configurer.networks]
        be.specific_address = configurer.address or Addresses.ANY
        return be

    def __init__(self, transport: Optional[Protocol] = None, protocol: Protocol = Protocol.ANY, name="", port=-1):
        self.transport = transport
        self.protocol = protocol
        self.service_name = name
        self.port_to_name = True
        self.service_port = port
        self.host_type = HostType.GENERIC
        self.con_type = ConnectionType.UNKNOWN
        self.authentication = False
        self.networks: List[Network] = []
        self.specific_address: AnyAddress = Addresses.ANY
        self.external_activity: Optional[ExternalActivity.BANNED] = None
        self.critical_parameter: List[SensitiveData] = []

    def as_multicast_(self, address: str, system: SystemBackend) -> ServiceBackend:
        """The protocol as multicast"""
        raise ConfigurationException(
            f"{self.service_name} cannot be broad/multicast")

    def get_service_(self, parent: HostBackend) -> ServiceBackend:
        """Create or get service builder"""
        old = parent.service_builders.get(
            (self.transport, self.service_port if self.port_to_name else -1))
        if old:
            return old
        b = self._create_service(parent)
        parent.service_builders[(self.transport, self.service_port)] = b
        b.entity.status = Status.EXPECTED
        assert b.entity.parent == parent.entity
        parent.entity.children.append(b.entity)
        if not b.entity.addresses:
            # E.g. DHCP service fills this oneself
            ep_add = EndpointAddress(self.specific_address, self.transport, self.service_port)
            b.entity.addresses.add(ep_add)
        if self.critical_parameter:
            # critical protocol parameters
            parent.use_data(SensitiveDataBackend(
                parent.system, self.critical_parameter))
        return b

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        s = ServiceBackend(parent,
                           parent.new_service_(self.service_name, self.service_port if self.port_to_name else -1))
        s.configurer = self
        s.entity.authentication = self.authentication
        s.entity.host_type = self.host_type
        s.entity.con_type = self.con_type
        if self.external_activity is not None:
            s.entity.external_activity = self.external_activity
        s.entity.protocol = self.protocol
        s.entity.networks = self.networks
        return s

    def __repr__(self):
        return f"{self.service_name}"


class ARPBackend(ProtocolBackend):
    """ARP protocol backend"""

    def __init__(self, _configurer: ARP, protocol=Protocol.ARP, broadcast_endpoint=False):
        super().__init__(Protocol.ARP, name="ARP")
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.broadcast_endpoint = broadcast_endpoint
        # ARP make requests and replies
        self.external_activity = ExternalActivity.UNLIMITED

    def get_service_(self, parent: HostBackend) -> ServiceBackend:
        if self.broadcast_endpoint:
            return super().get_service_(parent)
        host_s = super().get_service_(parent)
        # ARP can be broadcast, get or create the broadcast host and service
        bc_node = parent.system.get_host_(
            f"{HWAddresses.BROADCAST}", description="Broadcast")
        bc_s = bc_node.service_builders.get(
            (self.transport, self.service_port))
        # Three entities:
        # host_s: ARP service at host
        # bc_node: Broadcast logical node
        # bc_s: ARP service a the broadcast node
        if not bc_s:
            # create ARP service
            bc_node.new_address_(HWAddresses.BROADCAST)
            # anyone can make broadcasts (it does not reply)
            bc_node.entity.external_activity = ExternalActivity.OPEN
            bc_node.entity.host_type = HostType.ADMINISTRATIVE
            # ARP service at the broadcast node, but avoid looping back to ARPBackend
            bc_s = ARPBackend(
                ARP(), broadcast_endpoint=True).get_service_(bc_node)
            bc_s.entity.host_type = HostType.ADMINISTRATIVE
            bc_s.entity.con_type = ConnectionType.ADMINISTRATIVE
            bc_s.entity.external_activity = bc_node.entity.external_activity
            host_s.entity.external_activity = self.external_activity
        c_ok = any(c.source == host_s.entity for c in host_s.entity.get_parent_host().connections)
        if not c_ok:
            host_s >> bc_s  # # pylint: disable=pointless-statement
        return bc_s  # NOTE: the broadcast


class DHCPBackend(ProtocolBackend):
    """DHCP protocol backend"""

    def __init__(self, configurer: DHCP):
        super().__init__(Protocol.UDP, port=configurer.port, protocol=Protocol.DHCP, name="DHCP")
        # DHCP requests go to broadcast, thus the reply looks like request
        self.external_activity = ExternalActivity.UNLIMITED

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        host_s = ServiceBackend(parent, DHCPService(parent.entity))
        host_s.entity.external_activity = self.external_activity

        def create_source(host: HostBackend):
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


class DNSBackend(ProtocolBackend):
    """DNS protocol backend"""

    def __init__(self, configurer: DNS):
        super().__init__(Protocol.UDP, port=configurer.port, protocol=Protocol.DNS, name="DNS")
        self.external_activity = ExternalActivity.OPEN
        self.captive_portal = configurer.captive

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        dns_s = DNSService(parent.entity)
        dns_s.captive_portal = self.captive_portal
        s = ServiceBackend(parent, dns_s)
        s.entity.external_activity = self.external_activity
        return s


class EAPOLBackend(ProtocolBackend):
    """EAPOL protocol backend"""

    def __init__(self, configurer: EAPOL):
        super().__init__(Protocol.ETHERNET, port=0x888e, protocol=Protocol.EAPOL, name=configurer.name)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False


class HTTPBackend(ProtocolBackend):
    """HTTP protocol backend"""

    def __init__(self, configurer: HTTP):
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.HTTP, name=configurer.name)
        self.authentication = configurer.auth
        self.redirect_only = False

    def get_service_(self, parent: HostBackend) -> ServiceBackend:
        s = super().get_service_(parent)
        if self.redirect_only:
            # persistent property
            s.entity.set_property(Properties.HTTP_REDIRECT.verdict(
                explanation="HTTP redirect to TLS"))
        return s


class ICMPBackend(ProtocolBackend):
    """ICMP protocol backend"""

    def __init__(self, configurer: ICMP):
        super().__init__(Protocol.IP, port=1, protocol=Protocol.ICMP, name=configurer.name)
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        s = super()._create_service(parent)
        s.entity.name = "ICMP"  # a bit of hack...
        s.entity.host_type = HostType.ADMINISTRATIVE
        s.entity.con_type = ConnectionType.ADMINISTRATIVE
        # ICMP can be a service for other hosts
        s.entity.external_activity = max(
            self.external_activity, parent.entity.external_activity)
        return s


class IPBackend(ProtocolBackend):
    """IP protocol backend"""

    def __init__(self, configurer: IP):
        super().__init__(Protocol.IP, name=configurer.name)
        if configurer.administration:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class TLSBackend(ProtocolBackend):
    """TLS protocol backend"""

    def __init__(self, configurer: TLS):
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.TLS, name=configurer.name)
        self.authentication = configurer.auth
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("TLS-creds"))


class NTPBackend(ProtocolBackend):
    """NTP protocol backend"""

    def __init__(self, configurer: NTP):
        super().__init__(Protocol.UDP, port=configurer.port, protocol=Protocol.NTP, name=configurer.name)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN


class SSHBackend(ProtocolBackend):
    """SSH protocol backend"""

    def __init__(self, configurer: SSH):
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.SSH, name=configurer.name)
        self.authentication = True
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("SSH-creds"))


class TCPBackend(ProtocolBackend):
    """TCP protocol backend"""

    def __init__(self, configurer: TCP):
        super().__init__(Protocol.TCP, port=configurer.port, name=configurer.name)
        if configurer.administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class UDPBackend(ProtocolBackend):
    """UDP protocol backend"""

    def __init__(self, configurer: UDP):
        super().__init__(Protocol.UDP, port=configurer.port, name=configurer.name)
        if configurer.administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE

    def as_multicast_(self, address: str, system: SystemBackend) -> 'ServiceBackend':
        b = system.get_host_(address, description="Multicast")
        # Explicitly configured multicast nodes, at least are not administrative
        # b.entity.host_type = HostType.ADMINISTRATIVE
        addr = IPAddress.new(address)
        if addr not in b.entity.addresses:
            b.new_address_(addr)
        return self.get_service_(b)


class BLEAdvertisementBackend(ProtocolBackend):
    """BLE advertisement backend"""

    def __init__(self, configurer: BLEAdvertisement):
        super().__init__(Protocol.BLE, port=configurer.event_type,
                         name=configurer.name, protocol=Protocol.BLE)

    def as_multicast_(self, address: str, system: SystemBackend) -> 'ServiceBackend':
        b = system.get_host_(
            name="BLE Ads", description="Bluetooth LE Advertisements")
        b.new_address_(Addresses.BLE_Ad)
        b.entity.external_activity = ExternalActivity.PASSIVE
        return self.get_service_(b)


class ProtocolConfigurers:
    """Protocol configurers and backends"""
    Constructors = {
        ARP: ARPBackend,
        DHCP: DHCPBackend,
        DNS: DNSBackend,
        EAPOL: EAPOLBackend,
        HTTP: HTTPBackend,
        ICMP: ICMPBackend,
        IP: IPBackend,
        TLS: TLSBackend,
        NTP: NTPBackend,
        SSH: SSHBackend,
        TCP: TCPBackend,
        UDP: UDPBackend,
        BLEAdvertisement: BLEAdvertisementBackend,
    }


class OSBackend(OSBuilder):
    """OS builder backend"""
    def __init__(self, parent: HostBackend):
        self.component = OperatingSystem.get_os(parent.entity)

    def processes(self, owner_process: Dict[str, List[str]]) -> 'OSBuilder':
        self.component.process_map.update(owner_process)


class ClaimBackend(ClaimBuilder):
    """Claim builder"""

    def __init__(self, builder: 'ClaimSetBackend', explanation: str, verdict: Verdict, label: str,
                 authority=ClaimAuthority.MODEL):
        self.builder = builder
        self.authority = authority
        self.source = builder.sources.get(label)
        if self.source is None:
            self.source = EvidenceSource(f"Claims '{label}'", label=label)
            self.source.model_override = True  # sent by model, override from DB
            builder.sources[label] = self.source
        self.explanation = explanation
        self.property_keys: List[PropertyKey] = []
        self.locations: List[Entity] = []
        self.verdict = verdict
        builder.claim_builders.append(self)

    def key(self, *segments: str) -> Self:
        key = PropertyKey.create(segments)
        if key.is_protected():
            key = key.prefix_key(Properties.PREFIX_MANUAL)
        self.property_keys.append(key)
        return self

    def keys(self, *key: Tuple[str, ...]) -> Self:
        for seg in key:
            assert isinstance(seg, tuple), f"Bad key {seg}"
            k = PropertyKey.create(seg)
            if k.is_protected():
                k = k.prefix_key(Properties.PREFIX_MANUAL)
            self.property_keys.append(k)
        return self

    def verdict_ignore(self) -> Self:
        self.verdict = Verdict.IGNORE
        return self

    def verdict_pass(self) -> Self:
        self.verdict = Verdict.PASS
        return self

    def at(self, *locations: Union[SystemBackend, NodeBackend, ConnectionBackend]) -> 'Self':
        for lo in locations:
            if isinstance(lo, SystemBackend):
                loc = lo.system
            elif isinstance(lo, NodeBackend):
                loc = lo.entity
            else:
                loc = lo.connection
            self.locations.append(loc)
        return self

    def software(self, *locations: NodeBackend) -> 'Self':
        for lo in locations:
            for sw in Software.list_software(lo.entity):
                self.locations.append(sw)
        return self

    def vulnerabilities(self, *entry: Tuple[str, str]) -> Self:
        for com, cve in entry:
            self.property_keys.append(PropertyKey("vulnz", com, cve.lower()))
        return self

    # Backend methods

    def finish_loaders(self) -> SubLoader:
        """Finish by returning the loader to use"""
        this = self
        locations = self.locations
        keys = self.property_keys

        class ClaimLoader(SubLoader):
            """Loader for the claims here"""

            def __init__(self):
                super().__init__("Manual checks")
                self.source_label = this.source.label

            def load(self, registry: Registry, label_filter: LabelFilter):
                if not label_filter.filter(self.source_label):
                    return
                evidence = Evidence(this.source)
                for loc in locations:
                    for key in keys:
                        kv = PropertyKey.create(key.segments).verdict(
                            this.verdict, explanation=this.explanation)
                        ev = PropertyEvent(evidence, loc, kv)
                        registry.property_update(ev)
        return ClaimLoader()


class ClaimSetBackend(ClaimSetBuilder):
    """Builder for set of claims"""

    def __init__(self, builder: SystemBackend):
        self.builder = builder
        self.claim_builders: List[ClaimBackend] = []
        self.tool_plans: List[ToolPlanLoader] = []
        self.base_label = "explain"
        self.sources: Dict[str, EvidenceSource] = {}

    def set_base_label(self, base_label: str) -> Self:
        self.base_label = base_label
        return self

    def claim(self, explanation: str, verdict=Verdict.PASS) -> ClaimBackend:
        return ClaimBackend(self, explanation, verdict, self.base_label)

    def reviewed(self, explanation="", verdict=Verdict.PASS) -> ClaimBackend:
        return ClaimBackend(self, explanation, verdict, self.base_label, ClaimAuthority.MANUAL)

    def ignore(self, explanation="") -> ClaimBackend:
        return ClaimBackend(self, explanation, Verdict.IGNORE, self.base_label)

    def plan_tool(self, tool_name: str, group: Tuple[str, str], location: AbstractSelector,
                  *key: Tuple[str, ...]) -> ToolPlanLoader:
        sl = ToolPlanLoader(group)
        sl.location = location
        for k in key:
            pk = PropertyKey.create(k)
            pv = pk.verdict(Verdict.PASS, explanation=f"{tool_name} sets {pk}")
            sl.properties[pk] = pv[1]
        self.tool_plans.append(sl)
        return sl

    # Backend methods

    def finish_loaders(self) -> List[SubLoader]:
        """Finish"""
        ls = []
        ls.extend([cb.finish_loaders() for cb in self.claim_builders])
        ls.extend(self.tool_plans)
        return ls


class SystemBackendRunner(SystemBackend):
    """Backend for system builder"""

    def _parse_arguments(self, custom_arguments: Optional[List[str]]) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser()
        parser.add_argument("--read", "-r", action="append",
                            help="Read tool output from batch directories")
        parser.add_argument("--help-tools", action="store_true",
                            help="List tools read from batch")
        parser.add_argument("--def-loads", "-L", type=str,
                            help="Comma-separated list of tools to load")
        parser.add_argument("--with-files", "-w", action="store_true", help="Show relevant result files for verdicts")
        parser.add_argument("--dhcp", action="store_true",
                            help="Add default DHCP server handling")
        parser.add_argument("--dns", action="store_true",
                            help="Add default DNS server handling")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)

        parser.add_argument("--db", type=str, help="Connect to SQL database")
        parser.add_argument("--http-server", type=int,
                            help="Listen HTTP requests at port")
        parser.add_argument("--test-delay", type=int,
                            help="HTTP request artificial test delay, ms")
        parser.add_argument("--no-auth-ok", action="store_true",
                            help="Skip check for auth token in TDSAF_SERVER_API_KEY")

        parser.add_argument("--test-get", action="append",
                            help="Test API GET, repeat for many")
        parser.add_argument("--test-post", nargs=2, help="Test API POST")

        parser.add_argument(
            "--log-events", action="store_true", help="Log events")

        args = parser.parse_args(custom_arguments)
        logging.basicConfig(format='%(message)s', level=getattr(
            logging, args.log_level or 'INFO'))
        return args

    def run(self, custom_arguments: Optional[List[str]] = None):
        """Model is ready, run the checks"""
        args = self._parse_arguments(custom_arguments)
        if args.dhcp:
            self.any().serve(DHCP)
        if args.dns:
            self.any().serve(DNS)

        self.finish_()

        registry = Registry(Inspector(self.system))

        log_events = args.log_events
        if log_events:
            # print event log
            registry.logging.event_logger = registry.logger

        db_conn = args.db
        if db_conn:
            # connect to SQL database
            registry.logger.info("Connecting to database %s", db_conn)
            registry.database = SQLDatabase(db_conn)
        # finish loading after DB connection
        registry.finish_model_load()

        label_filter = LabelFilter(args.def_loads or "")

        # load file batches, if defined
        batch_import = BatchImporter(registry, label_filter=label_filter)
        for in_file in args.read or []:
            batch_import.import_batch(pathlib.Path(in_file))

        if args.help_tools:
            # print help and exit
            for label, sl in sorted(batch_import.evidence.items()):
                sl_s = ", ".join(sorted(set(s.name for s in sl)))
                print(f"{label:<20} {sl_s}")
            return

        # load product claims, then explicit loaders (if any)
        for sub in self.claim_set.finish_loaders():
            sub.load(registry, label_filter=label_filter)
        for ln in self.loaders:
            for sub in ln.subs:
                sub.load(registry, label_filter=label_filter)

        api = VisualizerAPI(registry, self.visualizer)
        if args.test_post:
            res, data = args.test_post
            request = APIRequest.parse(res)
            if data.strip().startswith("{"):
                # assuming JSON
                resp = api.api_post(request, io.BytesIO(data.encode()))
            else:
                # assuming file
                api.logger.info("POST file %s", data)
                resp = api.api_post_file(request, pathlib.Path(data))
            print(json.dumps(resp, indent=4))
            return
        if args.test_get:
            wid, hei = shutil.get_terminal_size()[0], 0  # only width specified
            for res in args.test_get:
                api_req = APIRequest.parse(res)
                api_req.set_param("screen", f"{wid}x{hei}")
                print(api.api_get(api_req, pretty=True))
            return

        if custom_arguments is not None:
            # custom arguments, return without 'running' anything
            return

        with_files = bool(args.with_files)
        report = Report(registry)
        report.source_count = 3 if with_files else 0
        report.print_report(sys.stdout)

        if args.http_server:
            server = HTTPServerRunner(
                api, port=args.http_server, no_auth_ok=args.no_auth_ok)
            server.component_delay = (args.test_delay or 0) / 1000
            server.run()
