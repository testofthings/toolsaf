"""Model builder backend"""

import argparse
import ipaddress
import logging
import pathlib
import sys
import inspect
import json

from typing import Any, Callable, Dict, List, Optional, Self, Tuple, Union, cast, Set

from toolsaf.common.address import (AddressAtNetwork, Addresses, AnyAddress, DNSName, EndpointAddress, EntityTag,
                                  HWAddress, HWAddresses, IPAddress, IPAddresses, Network, Protocol, PseudoAddress)
from toolsaf.common.basics import ConnectionType, ExternalActivity, HostType, Status
from toolsaf.adapters.batch_import import BatchData, BatchImporter, LabelFilter
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.core.components import CookieData, Cookies, DataReference, StoredData, OperatingSystem, Software
from toolsaf.common.release_info import ReleaseInfo
from toolsaf.common.property import PropertyVerdictValue
from toolsaf.core.event_logger import EventLogger
from toolsaf.core.serializer.event_serializers import EventSerializer
from toolsaf.core.serializer.model_serializers import IoTSystemSerializer
from toolsaf.main import (ARP, DHCP, DNS, EAPOL, ICMP, NTP, SSH, HTTP, TCP, UDP, IP, TLS, MQTT, FTP,
                        BLEAdvertisement, ConnectionBuilder,
                        CookieBuilder, HostBuilder, NetworkBuilder, NodeBuilder, NodeVisualBuilder,
                        ConfigurationException, OSBuilder, Proprietary, ProtocolConfigurer, ProtocolType,
                        SensitiveDataBuilder, ServiceBuilder, ServiceGroupBuilder, ServiceOrGroup,
                        SoftwareBuilder, SystemBuilder, IgnoreRulesBuilder)
from toolsaf.core.main_tools import EvidenceLoader, NodeManipulator
from toolsaf.core.model import Addressable, Connection, Host, IoTSystem, SensitiveData, Service
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.core.registry import Registry
from toolsaf.core.inspector import Inspector
from toolsaf.core.result import Report
from toolsaf.core.components import SoftwareComponent
from toolsaf.core.services import DHCPService, DNSService
from toolsaf.core.sql_database import SQLDatabase
from toolsaf.core.online_resources import OnlineResource
from toolsaf.common.verdict import Verdict
from toolsaf.common.android import MobilePermissions
from toolsaf.adapters.spdx_reader import SPDXJson
from toolsaf.diagram_visualizer import DiagramVisualizer
from toolsaf.core.ignore_rules import IgnoreRules
from toolsaf.core.uploader import Uploader


class SystemBackend(SystemBuilder):
    """System model builder"""

    def __init__(self, name: str="Unnamed system") -> None:
        self.system = IoTSystem(name)
        self.hosts_by_name: Dict[str, 'HostBackend'] = {}
        self.entity_by_address: Dict[AddressAtNetwork, 'NodeBackend'] = {}
        self.attachments: List[pathlib.Path] = []
        self.diagram = DiagramVisualizer(self)
        self.loaders: List[EvidenceLoader] = []
        self.protocols: Dict[Any, 'ProtocolBackend'] = {}
        self.ignore_backend = IgnoreRulesBackend()

    def network(self, subnet: str="", ip_mask: Optional[str] = None) -> 'NetworkBuilder':
        if subnet:
            nb = NetworkBackend(self, subnet)
        else:
            nb = NetworkBackend(self)
        if ip_mask:
            nb.mask(ip_mask)
        return nb

    def device(self, name: str="") -> 'HostBackend':
        name = name or self._free_host_name("Device")
        b = self.get_host_(name, "Internet Of Things device")
        b.entity.host_type = HostType.DEVICE
        # E.g. ICMP ping is fine, but no reply unless in the model
        b.entity.external_activity = ExternalActivity.PASSIVE
        return b

    def backend(self, name: str="") -> 'HostBackend':
        name = name or self._free_host_name("Backend")
        b = self.get_host_(name, "Backend service over Internet")
        b.entity.host_type = HostType.REMOTE
        b.entity.external_activity = ExternalActivity.OPEN
        return b

    def mobile(self, name: str="") -> 'HostBackend':
        name = name or self._free_host_name("Mobile")
        b = self.get_host_(name, "Mobile application")
        b.entity.host_type = HostType.MOBILE
        # who know what apps etc.
        b.entity.external_activity = ExternalActivity.UNLIMITED
        return b

    def browser(self, name: str="") -> 'HostBackend':
        name = name or self._free_host_name("Browser")
        b = self.get_host_(name, "Browser")
        b.entity.host_type = HostType.BROWSER
        return b

    def any(self, name: str="", node_type: Optional[HostType] = None) -> 'HostBackend':
        name = name or self._free_host_name("Environment")
        b = self.get_host_(name, "Environment")
        b.entity.any_host = True
        b.entity.host_type = HostType.ADMINISTRATIVE if node_type is None else node_type
        # might serve other network nodes
        b.entity.external_activity = ExternalActivity.UNLIMITED
        return b

    def infra(self, name: str="") -> 'HostBackend':
        name = name or self._free_host_name("Infra")
        b = self.get_host_(name, "Part of the testing infrastructure")
        b.entity.host_type = HostType.ADMINISTRATIVE
        b.entity.external_activity = ExternalActivity.UNLIMITED
        b.entity.match_priority = 5
        return b

    def data(self, names: List[str], personal: bool=False, password: bool=False) -> 'SensitiveDataBackend':
        d = [SensitiveData(n, personal=personal, password=password)
             for n in names]
        return SensitiveDataBackend(self, d)

    def online_resource(self, name: str, url: str, keywords: List[str]) -> Self:
        if len(keywords) == 0:
            raise ConfigurationException("You must provide at least 1 keyword")
        self.system.online_resources.append(
            OnlineResource(name, url, keywords)
        )
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

    def diagram_visualizer(self) -> 'DiagramVisualizer':
        return self.diagram

    def load(self) -> 'EvidenceLoader':
        el = EvidenceLoader(self)
        self.loaders.append(el)
        return el

    def ignore(self, file_type: str) -> 'IgnoreRulesBackend':
        self.ignore_backend.new_rule(file_type)
        return self.ignore_backend

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
                # NOTE: All constructors are assumed to with parameterless
                p = protocol()  # type: ignore [call-arg]
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

    def _check_unique_under_parent(self, host: Host) -> None:
        """Check that all children of the host have unique names"""
        child_names: Set[str] = set()
        for child in host.children:
            if child.name in child_names:
                raise ConfigurationException(f"Name {child.name} used more than once for {host.name}")
            child_names.add(child.name)

    def finish_(self) -> None:
        """Finish the model"""
        host_names: Set[str] = set()
        hosts = self.system.get_hosts()
        # each real host must have software and names under parents are unique
        for h in hosts:
            if not h.any_host and h.host_type != HostType.BROWSER:
                Software.ensure_default_software(h)
            if h.name in host_names:
                raise ConfigurationException(f"Name {h.name} used more than once")
            host_names.add(h.name)
            self._check_unique_under_parent(h)

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

    def __init__(self, entity: Addressable, system: SystemBackend) -> None:
        super().__init__(system)
        self.system: SystemBackend = system
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
            c: ConnectionBackend
            for t in target.services:
                c = t.connection_(self)
            return c
        assert isinstance(target, ServiceBackend)
        return target.connection_(self)

    # Backend methods

    def get_node(self) -> Addressable:
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

    def new_service_(self, name: str, port: int=-1) -> Service:
        """Create new service here"""
        return Service(Service.make_name(name, port), self.entity)

    def get_software(self) -> Software:
        """Get the software entity"""
        return self.software().sw

    def __repr__(self) -> str:
        return self.entity.__repr__()


class ServiceBackend(NodeBackend, ServiceBuilder):
    """Service builder backend"""

    def __init__(self, host: 'HostBackend', service: Service) -> None:
        NodeBackend.__init__(self, service, host.system)
        ServiceBuilder.__init__(self, host.system)
        self.entity: Service = service
        self.entity.match_priority = 10
        self.entity.external_activity = host.entity.external_activity
        self.parent: HostBackend = host
        self.multicast_protocol: Optional[ProtocolConfigurer] = None  # in broadcast 'source' services
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

    def __init__(self, services: List[ServiceBackend]) -> None:
        assert len(services) > 0, "Empty list of services"
        self.services = services

    def __truediv__(self, other: ServiceOrGroup | ProtocolType) -> 'ServiceGroupBackend':
        g = self.services.copy()
        if isinstance(other, ServiceGroupBackend):
            g.extend(other.services)
        elif isinstance(other, ServiceBackend):
            g.append(other)
        else:
            pro_type = cast(ProtocolType, other)
            system = self.services[0].system
            conf = system.get_protocol_backend(pro_type)
            g.append(conf.get_service_(self.services[0].parent))
        return ServiceGroupBackend(g)

    # Backend methods

    def __repr__(self) -> str:
        return " / ".join([f"{s.entity.name}" for s in self.services])


class HostBackend(NodeBackend, HostBuilder):
    """Host builder backend"""

    def __init__(self, entity: Host, system: SystemBackend) -> None:
        NodeBackend.__init__(self, entity, system)
        HostBuilder.__init__(self, system)
        self.entity: Host = entity
        system.system.children.append(entity)
        entity.status = Status.EXPECTED
        system.hosts_by_name[entity.name] = self
        if DNSName.looks_like(entity.name):
            self.name(entity.name)
        self.service_builders: Dict[Tuple[Protocol, int], ServiceBackend] = {}

    def hw(self, address: str) -> Self:
        self.new_address_(HWAddress.new(address))
        return self

    def ip(self, address: str) -> Self:
        self.new_address_(IPAddress.new(address))
        return self

    def serve(self, *protocols: ProtocolType) -> Self:
        for p in protocols:
            self / p  # pylint: disable=pointless-statement
        return self

    def multicast(self, address: str, protocol: 'ProtocolConfigurer') -> 'ServiceBackend':
        conf = self.system.get_protocol_backend(protocol)
        return conf.as_multicast_(address, self)

    def broadcast(self, protocol: 'ProtocolConfigurer') -> 'ServiceBackend':
        conf = self.system.get_protocol_backend(protocol)
        add = f"{IPAddresses.BROADCAST}" if conf.transport == Protocol.UDP \
            else f"{HWAddresses.BROADCAST}"
        return self.multicast(add, protocol)

    def os(self) -> OSBuilder:
        return OSBackend(self)

    def __lshift__(self, multicast: ServiceBuilder) -> 'ConnectionBackend':
        assert isinstance(multicast, ServiceBackend)
        mc = multicast.entity
        assert mc.multicast_source and multicast.multicast_protocol, "Can only receive multicast"
        # create a service for multicast
        sb = self / multicast.multicast_protocol
        # the target is listening broadcast address + port (if any)
        sb.entity.addresses.clear()
        for ep in mc.addresses:
            sb.entity.addresses.add(ep.change_host(mc.multicast_source))
        c = multicast.parent >> sb  # broadcast is not by any means from the multicast port
        return c

    def cookies(self) -> 'CookieBackend':
        return CookieBackend(self)

    def use_data(self, *data: SensitiveDataBuilder) -> Self:
        for db in data:
            db.used_by(hosts=[self])
        return self

    def __truediv__(self, protocol: ProtocolType) -> ServiceBackend:
        conf = self.system.get_protocol_backend(protocol)
        return conf.get_service_(self)

    def ignore_name_requests(self, *name: str) -> Self:
        self.entity.ignore_name_requests.update([DNSName(n) for n in name])
        return self

    def set_property(self, *key: str) -> Self:
        p = PropertyKey.create(key).persistent()
        self.entity.set_property(p.verdict())  # inconclusive
        return self

    def set_permissions(self, *permissions: MobilePermissions) -> Self:
        """Set permissions for a mobile application"""
        if self.get_node().host_type != HostType.MOBILE:
            raise NotImplementedError("set_permissions only supports mobile at the moment")
        sw = self.get_software()
        for permission in permissions:
            sw.permissions.add(permission.value)
        return self


class SensitiveDataBackend(SensitiveDataBuilder):
    """Sensitive data builder backend"""

    def __init__(self, parent: SystemBackend, data: List[SensitiveData]) -> None:
        super().__init__(parent)
        self.parent: SystemBackend = parent
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
            assert isinstance(h, HostBackend)
            storage = StoredData.get_data(h.entity)
            for d in self.data:
                storage.sub_components.append(DataReference(h.entity, d))
        return self


class ConnectionBackend(ConnectionBuilder):
    """Connection builder backendq"""

    def __init__(self, connection: Connection, ends: Tuple[NodeBackend, ServiceBackend]) -> None:
        self.connection = connection
        self.ends = ends
        self.ends[0].system.system.originals.add(connection)

    def logical_only(self) -> Self:
        self.connection.con_type = ConnectionType.LOGICAL
        return self

    def __repr__(self) -> str:
        return self.connection.__repr__()


class NetworkBackend(NetworkBuilder):
    """Network or subnet backend"""
    def __init__(self, parent: SystemBackend, name: str="") -> None:
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

    def __init__(self, parent: NodeBackend, software_name: str) -> None:
        sw = Software.get_software(parent.entity, software_name)
        if sw is None:
            # all hosts have software
            sw = Software(parent.entity, software_name)
            parent.entity.add_component(sw)
        self.sw: Software = sw
        self.parent = parent

    def updates_from(self, source: Union[ConnectionBuilder, ServiceBuilder, HostBuilder]) -> Self:
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

    def update_frequency(self, days: int) -> Self:
        """Target update frequency, days"""
        self.sw.info.interval_days = days
        return self

    def __sbom_from_list(self, components: List[str]) -> None:
        for c in components:
            self.sw.components[c] = SoftwareComponent(c, version="")
            key = PropertyKey("component", c)
            self.sw.properties[key] = PropertyVerdictValue(Verdict.INCON)

    def __sbom_from_file(self, statement_file_path: pathlib.Path, file_path: str) -> None:
        try:
            with (statement_file_path / file_path).resolve().open("rb") as f:
                for c in SPDXJson(f).read():
                    self.sw.components[c.name] = c
                    key = PropertyKey("component", c.name)
                    self.sw.properties[key] =\
                        PropertyVerdictValue(Verdict.INCON, explanation=f"version {c.version}")
        except FileNotFoundError as e:
            raise ConfigurationException(f"Could not find SBOM file {e.filename}") from e

    def sbom(self, components: Optional[List[str]]=None, file_path: str="") -> Self:
        """Add an SBOM from given list or SPDX JSON file.
           file_path is relative to statement"""
        if not components and not file_path:
            raise ConfigurationException("Provide either components list of file")
        if file_path and not file_path.endswith(".json"):
            raise ConfigurationException("Given SBOM file must be SPDX JSON")

        if components:
            self.__sbom_from_list(components)
        else:
            statement_file_path = pathlib.Path(inspect.stack()[1].filename).parent
            self.__sbom_from_file(statement_file_path, file_path)

        return self

    # Backend methods

    def get_software(self, _name: Optional[str] = None) -> Software:
        """Get the software entity"""
        return self.sw


class CookieBackend(CookieBuilder):
    """Cookie builder backend"""

    def __init__(self, builder: HostBackend) -> None:
        self.builder = builder
        self.component = Cookies.cookies_for(builder.entity)

    def set(self, cookies: Dict[str, Tuple[str, str, str]]) -> Self:
        for name, p in cookies.items():
            self.component.cookies[name] = CookieData(p[0], p[1], p[2])
        return self


class NodeVisualBackend(NodeVisualBuilder):
    """Node visual builder backend"""

    def __init__(self, entity: NodeBackend) -> None:
        self.entity = entity
        self.image_url: Optional[str] = None
        self.image_scale: int = 100

    def hide(self) -> Self:
        self.entity.entity.visual = False
        return self

    def image(self, url: str, scale: int=100) -> Self:
        self.image_url = url
        self.image_scale = scale
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
        assert isinstance(be, ProtocolBackend)
        return be

    def __init__(self, transport: Protocol, protocol: Protocol = Protocol.ANY, name: str="", port: int=-1) -> None:
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
        self.external_activity: Optional[ExternalActivity] = None
        self.critical_parameter: List[SensitiveData] = []

    def as_multicast_(self, address: str, host: 'HostBackend') -> 'ServiceBackend':
        """The protocol as multicast"""
        raise ConfigurationException(
            f"{self.service_name} cannot be broad/multicast")

    def get_service_(self, parent: HostBackend) -> ServiceBackend:
        """Create or get service builder"""
        key = self.transport, (self.service_port if self.port_to_name else -1)
        old = parent.service_builders.get(key)
        if old:
            return old
        b = self._create_service(parent)
        parent.service_builders[key] = b
        b.entity.status = Status.EXPECTED
        assert b.entity.parent == parent.entity
        parent.entity.children.append(b.entity)
        if not b.entity.addresses:
            # E.g. DHCP service fills this oneself
            assert self.transport, "transport was None"
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
        s.entity.authentication = self.authentication
        s.entity.host_type = self.host_type
        s.entity.con_type = self.con_type
        if self.external_activity is not None:
            s.entity.external_activity = self.external_activity
        s.entity.protocol = self.protocol
        s.entity.networks = self.networks
        return s

    def __repr__(self) -> str:
        return f"{self.service_name}"


class ARPBackend(ProtocolBackend):
    """ARP protocol backend"""

    def __init__(self, _configurer: ARP, protocol: Protocol=Protocol.ARP, broadcast_endpoint: bool=False) -> None:
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
            assert self.external_activity, "external activity was None"
            host_s.entity.external_activity = self.external_activity
        c_ok = any(c.source == host_s.entity for c in host_s.entity.get_parent_host().connections)
        if not c_ok:
            host_s >> bc_s  # # pylint: disable=pointless-statement
        return bc_s  # NOTE: the broadcast


class DHCPBackend(ProtocolBackend):
    """DHCP protocol backend"""

    def __init__(self, configurer: DHCP) -> None:
        super().__init__(Protocol.UDP, port=configurer.port, protocol=Protocol.DHCP, name="DHCP")
        # DHCP requests go to broadcast, thus the reply looks like request
        self.external_activity = ExternalActivity.UNLIMITED

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        host_s = ServiceBackend(parent, DHCPService(parent.entity))
        assert self.external_activity, "external activity was None"
        host_s.entity.external_activity = self.external_activity

        def create_source(host: HostBackend) -> ServiceBackend:
            # DHCP client uses specific port 68 for requests
            src = UDP(port=68, name="DHCP")
            cs = host / src
            cs.entity.host_type = HostType.ADMINISTRATIVE
            cs.entity.con_type = ConnectionType.ADMINISTRATIVE
            cs.entity.client_side = True
            return cs
        host_s.source_fixer = create_source
        return host_s


class DNSBackend(ProtocolBackend):
    """DNS protocol backend"""

    def __init__(self, configurer: DNS) -> None:
        super().__init__(Protocol.UDP, port=configurer.port, protocol=Protocol.DNS, name="DNS")
        self.external_activity = ExternalActivity.OPEN
        self.captive_portal = configurer.captive

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        dns_s = DNSService(parent.entity)
        dns_s.captive_portal = self.captive_portal
        s = ServiceBackend(parent, dns_s)
        assert self.external_activity, "external activity was None"
        s.entity.external_activity = self.external_activity
        return s


class EAPOLBackend(ProtocolBackend):
    """EAPOL protocol backend"""

    def __init__(self, configurer: EAPOL) -> None:
        super().__init__(Protocol.ETHERNET, port=0x888e, protocol=Protocol.EAPOL, name=configurer.name)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False


class FTPBackend(ProtocolBackend):
    """FTP protocol backend"""

    def __init__(self, configurer: FTP) -> None:
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.FTP, name=configurer.name)

class HTTPBackend(ProtocolBackend):
    """HTTP protocol backend"""

    def __init__(self, configurer: HTTP) -> None:
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.HTTP, name=configurer.name)
        self.authentication = bool(configurer.auth)
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

    def __init__(self, configurer: ICMP) -> None:
        super().__init__(Protocol.IP, port=1, protocol=Protocol.ICMP, name=configurer.name)
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        s = super()._create_service(parent)
        s.entity.name = "ICMP"  # a bit of hack...
        s.entity.host_type = HostType.ADMINISTRATIVE
        s.entity.con_type = ConnectionType.ADMINISTRATIVE
        # ICMP can be a service for other hosts
        assert self.external_activity, "external activity was None"
        s.entity.external_activity = max(
            self.external_activity, parent.entity.external_activity)
        return s


class IPBackend(ProtocolBackend):
    """IP protocol backend"""

    def __init__(self, configurer: IP) -> None:
        super().__init__(Protocol.IP, name=configurer.name)
        if configurer.administration:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class MQTTBackend(ProtocolBackend):
    """MQTT protocol backend"""

    def __init__(self, configurer: MQTT) -> None:
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.MQTT, name=configurer.name)



class TLSBackend(ProtocolBackend):
    """TLS protocol backend"""

    def __init__(self, configurer: TLS) -> None:
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.TLS, name=configurer.name)
        self.authentication = bool(configurer.auth)
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("TLS-creds"))


class NTPBackend(ProtocolBackend):
    """NTP protocol backend"""

    def __init__(self, configurer: NTP) -> None:
        super().__init__(Protocol.UDP, port=configurer.port, protocol=Protocol.NTP, name=configurer.name)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN


class SSHBackend(ProtocolBackend):
    """SSH protocol backend"""

    def __init__(self, configurer: SSH) -> None:
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.SSH, name=configurer.name)
        self.authentication = True
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("SSH-creds"))


class TCPBackend(ProtocolBackend):
    """TCP protocol backend"""

    def __init__(self, configurer: TCP) -> None:
        super().__init__(Protocol.TCP, port=configurer.port, name=configurer.name)
        if configurer.administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class UDPBackend(ProtocolBackend):
    """UDP protocol backend"""

    def __init__(self, configurer: UDP) -> None:
        super().__init__(Protocol.UDP, port=configurer.port, name=configurer.name)
        self.configurer = configurer
        if configurer.administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE

    def as_multicast_(self, address: str, host: HostBackend) -> 'ServiceBackend':
        sb = self.get_service_(host)
        addr = IPAddress.new(address)
        sb.entity.multicast_source = addr
        sb.entity.name += " multicast"
        sb.multicast_protocol = self.configurer
        return sb


class BLEAdvertisementBackend(ProtocolBackend):
    """BLE advertisement backend"""

    def __init__(self, configurer: BLEAdvertisement) -> None:
        super().__init__(Protocol.BLE, port=configurer.event_type,
                         name=configurer.name, protocol=Protocol.BLE)
        self.configurer = configurer

    def as_multicast_(self, _address: str, host: HostBackend) -> 'ServiceBackend':
        sb = self.get_service_(host)
        sb.entity.name += " multicast"
        sb.entity.multicast_source = Addresses.BLE_Ad
        sb.multicast_protocol = self.configurer
        return sb


class ProprietaryProtocolBackend(ProtocolBackend):
    """Proprietary protocol backend"""

    def __init__(self, configurer: Proprietary) -> None:
        super().__init__(Protocol.OTHER, port=configurer.port, name=configurer.name)
        self.configurer = configurer

    def as_multicast_(self, address: str, host: HostBackend) -> 'ServiceBackend':
        # play along also with multicast
        sb = self.get_service_(host)
        sb.entity.name += " multicast"
        sb.entity.multicast_source = PseudoAddress(address, multicast=True)
        sb.multicast_protocol = self.configurer
        return sb

class ProtocolConfigurers:
    """Protocol configurers and backends"""
    Constructors = {
        ARP: ARPBackend,
        DHCP: DHCPBackend,
        DNS: DNSBackend,
        EAPOL: EAPOLBackend,
        FTP: FTPBackend,
        HTTP: HTTPBackend,
        ICMP: ICMPBackend,
        IP: IPBackend,
        MQTT: MQTTBackend,
        TLS: TLSBackend,
        NTP: NTPBackend,
        SSH: SSHBackend,
        TCP: TCPBackend,
        UDP: UDPBackend,
        BLEAdvertisement: BLEAdvertisementBackend,
        Proprietary: ProprietaryProtocolBackend,
    }


class OSBackend(OSBuilder):
    """OS builder backend"""
    def __init__(self, parent: HostBackend) -> None:
        self.component = OperatingSystem.get_os(parent.entity)

    def processes(self, owner_process: Dict[str, List[str]]) -> Self:
        assert self.component, "component was None"
        self.component.process_map.update(owner_process)
        return self


class IgnoreRulesBackend(IgnoreRulesBuilder):
    """Collection of ignore rules"""
    def __init__(self) -> None:
        self.ignore_rules = IgnoreRules()

    def new_rule(self, file_type: str) -> Self:
        """Create a new rule"""
        self.ignore_rules.new_rule(file_type)
        return self

    def properties(self, *properties: Tuple[str, ...]) -> Self:
        self.ignore_rules.properties(*properties)
        return self

    def at(self, *locations: Union[SystemBuilder, NodeBuilder, ConnectionBuilder]) -> Self:
        for location in locations:
            if isinstance(location, SystemBackend):
                self.ignore_rules.at(location.system)
            elif isinstance(location, NodeBackend):
                self.ignore_rules.at(location.entity)
            elif isinstance(location, SoftwareBackend):
                self.ignore_rules.at(location.sw)
            elif isinstance(location, ConnectionBackend):
                self.ignore_rules.at(location.connection)
            else:
                raise ConfigurationException(f"Unsupported value given ({location})")
        return self

    def because(self, explanation: str) -> Self:
        self.ignore_rules.because(explanation)
        return self

    def get_rules(self) -> IgnoreRules:
        """Get the ignore rules"""
        return self.ignore_rules


class LoadedData:
    """Loaded data for programmatic invoker"""
    def __init__(self, system: IoTSystem, log_access: EventLogger, batches: List[BatchData]):
        self.system = system
        self.log_access = log_access
        self.batches = batches


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
        parser.add_argument("-s", "--show", type=lambda s: s.split(","), default=[],
                            help="Show additional info in output. Valid values: all, properties, ignored, irrelevant")
        parser.add_argument("--no-truncate", action="store_true",
                            help="Disables output text truncation")
        parser.add_argument("-c", "--color", action="store_true",
                            help="Keep colors in output even when output is piped")
        parser.add_argument("-C", "--create-diagram", const="png", nargs="?", choices=["png", "jpg", "pdf"],
                            help="Creat a diagram of a security statement with given file format. Default is png")
        parser.add_argument("-S", "--show-diagram", const="png", nargs="?", choices=["png", "jpg", "pdf"],
                            help="Display the visualizer's output. Can also set file format. Default is png")
        parser.add_argument("-N", "--diagram-name", type=str,
                            help="File name for created diagram. Default is the system's name")
        parser.add_argument("--dhcp", action="store_true",
                            help="Add default DHCP server handling")
        parser.add_argument("--dns", action="store_true",
                            help="Add default DNS server handling")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)
        parser.add_argument("--statement-json", action="store_true", help="Dump security statement JSON to stdout")
        parser.add_argument("-u", "--upload", nargs="?", const=True,
                            help="Upload statement. You can provide the path to your API key file with this flag.")
        parser.add_argument("--db", type=str, help="Connect to SQL database")
        parser.add_argument(
            "--log-events", action="store_true", help="Log events")

        args = parser.parse_args(custom_arguments)
        logging.basicConfig(format='%(message)s', level=getattr(
            logging, args.log_level or 'INFO'))
        return args

    def run(self, custom_arguments: Optional[List[str]] = None) -> Optional[LoadedData]:
        """Model is ready, run the checks, return data for programmatic caller"""
        args = self._parse_arguments(custom_arguments)
        if args.dhcp:
            self.any().serve(DHCP)
        if args.dns:
            self.any().serve(DNS)

        self.finish_()

        registry = Registry(Inspector(self.system, self.ignore_backend.get_rules()))

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
            return None

        # load explicit loaders (if any)
        for ln in self.loaders:
            for sub in ln.subs:
                sub.load(registry, label_filter=label_filter)

        load_data = LoadedData(self.system, registry.logging, batch_import.batch_data)

        if args.statement_json:
            # dump security statement JSON
            ser = IoTSystemSerializer(self.system)
            stream = SerializerStream(ser)
            for js in stream.write(self.system):
                print(json.dumps(js, indent=4))
            # dump events, if any
            if registry.logging.logs:
                log_ser = EventSerializer()
                stream = SerializerStream(log_ser, context=stream.context)
                for log in registry.logging.logs:
                    for js in log_ser.write_event(log.event, stream):
                        print(json.dumps(js, indent=4))
        else:
            with_files = bool(args.with_files)
            report = Report(registry)
            report.source_count = 3 if with_files else 0
            report.show = args.show
            report.no_truncate = bool(args.no_truncate)
            report.use_color_flag = bool(args.color)
            report.print_report(sys.stdout)

        if custom_arguments is not None:
            # custom arguments, return without 'running' anything
            return load_data

        if args.create_diagram is not None or args.show_diagram is not None:
            self.diagram.set_outformat(args.create_diagram, args.show_diagram)
            self.diagram.set_file_name(args.diagram_name)
            self.diagram.show = bool(args.show_diagram)
            self.diagram.create_diagram()

        if args.upload:
            uploader = Uploader(statement_name=self.system.name)
            uploader.do_pre_procedures(args.upload)
            uploader.upload_statement()

            ser = IoTSystemSerializer(self.system)
            system_stream = SerializerStream(ser)
            uploader.upload_system(list(system_stream.write(self.system)))

            if registry.logging.logs:
                log_ser = EventSerializer()
                event_stream = SerializerStream(log_ser, context=system_stream.context)
                events = []
                for log in registry.logging.logs:
                    events += list(log_ser.write_event(log.event, event_stream))
                uploader.upload_logs(events)

        return load_data
