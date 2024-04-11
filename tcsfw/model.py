"""Model classes"""

import ipaddress
import itertools
import re
from typing import List, Set, Optional, Tuple, TypeVar, Callable, Dict, Any, Self, Iterable, Iterator
from urllib.parse import urlparse

from tcsfw.address import AnyAddress, Addresses, EndpointAddress, Protocol, IPAddress, HWAddress, DNSName
from tcsfw.basics import ConnectionType, ExternalActivity, HostType, Status
from tcsfw.entity import Entity
from tcsfw.property import PropertyKey
from tcsfw.traffic import Flow, EvidenceSource
from tcsfw.verdict import Verdict


class Connection(Entity):
    """A connection from source to target"""
    def __init__(self, source: 'Addressable', target: 'Addressable') -> None:
        super().__init__()
        self.concept_name = "connection"
        self.source = source
        self.target = target
        self.con_type = ConnectionType.UNKNOWN

    def is_original(self) -> bool:
        """Is this entity originally defined in the model?"""
        system = self.source.get_system()
        return self in system.originals

    def is_relevant(self, ignore_ends=False) -> bool:
        """Is this connection relevant, i.e. not placeholder or external?"""
        if self.status in {Status.EXPECTED, Status.UNEXPECTED}:
            return True
        if self.status == Status.PLACEHOLDER:
            return False  # placeholder is never relevant
        if ignore_ends:
            return False
        return self.source.is_relevant() or self.target.is_relevant()

    def is_expected(self) -> bool:
        """Is the connection expected?"""
        return self.status == Status.EXPECTED

    def is_encrypted(self) -> bool:
        """Is an encrypted connection?"""
        t = self.target
        return isinstance(t, Service) and t.is_encrypted()

    def is_end(self, entity: 'NetworkNode') -> bool:
        """Is given entity either end of the connection?"""
        return entity in {self.source, self.target}

    def reset_connection(self, system: 'IoTSystem'):
        """Reset this connection"""
        self.reset()
        if self not in system.originals:
            self.status = Status.PLACEHOLDER

    def long_name(self) -> str:
        """A long name for human consumption"""
        return f"{self.source.long_name()} => {self.target.long_name()}"


T = TypeVar("T")


class SensitiveData:
    """Piece of sensitive, security-relevant, data"""
    def __init__(self, name: str, personal=False, password=False):
        assert not (personal and password), "Data cannot be both 'personal' and 'password'"
        self.name = name
        self.personal = personal
        self.password = password

    def __repr__(self):
        return self.name


class NodeComponent(Entity):
    """Node internal components"""
    def __init__(self, entity: 'NetworkNode', name: str):
        super().__init__()
        self.entity = entity
        self.name = name
        self.sub_components: List[NodeComponent] = []
        self.status = Status.EXPECTED

    def get_children(self) -> Iterable['Entity']:
        return self.sub_components

    def long_name(self) -> str:
        return self.name

    def info_string(self) -> str:
        """Potentially multi-line information string"""
        return self.name

    def add_sub(self, component: 'NodeComponent') -> 'NodeComponent':
        """Add new sub-component"""
        self.sub_components.append(component)
        return component

    def reset(self):
        """Reset model"""
        super().reset()
        for s in self.sub_components:
            s.reset()

    def __repr__(self):
        return self.long_name()


class NetworkNode(Entity):
    """Network node in the model"""
    def __init__(self, name: str):
        super().__init__()
        self.name = name
        self.host_type = HostType.GENERIC
        self.description = ""
        self.match_priority = 0
        self.visual = False  # show visual image?
        self.children: List[Addressable] = []
        self.components: List[NodeComponent] = []
        self.external_activity = ExternalActivity.BANNED

    def get_children(self) -> Iterable['Entity']:
        return itertools.chain(self.children, self.components)

    def iterate_all(self) -> Iterator['Entity']:
        """Iterate all entities"""
        yield self
        for c in self.children:
            if c.status != Status.PLACEHOLDER:
                yield from c.iterate_all()
        for c in self.components:
            if c.status != Status.PLACEHOLDER:
                yield c

    def long_name(self):
        """Get longer name, or at least the name"""
        return self.name

    def get_hosts(self, include_external=True) -> List['Host']:
        """Get hosts"""
        return [c for c in self.children if isinstance(c, Host) and (include_external or c.is_relevant())]

    def is_original(self) -> bool:
        """Is this entity originally defined in the model?"""
        return self in self.get_system().originals

    def is_global(self) -> bool:
        """Is globally addressable thing?"""
        return False

    def is_multicast(self) -> bool:
        """Is a multicast target rather than real host?"""
        return False

    def is_relevant(self) -> bool:
        return self.status in {Status.EXPECTED, Status.UNEXPECTED}

    def get_connections(self, relevant_only=True) -> List[Connection]:
        """Get relevant conneciions"""
        cs = []
        for c in self.children:
            cs.extend(c.get_connections(relevant_only))
        return cs

    def get_system(self) -> 'IoTSystem':
        """Access the system-level"""
        raise NotImplementedError()

    def set_external_activity(self, value: ExternalActivity) -> Self:
        """Set the allowed external activity level"""
        self.external_activity = value
        for c in self.children:
            c.external_activity = value
        return self

    def merge_in(self, entity: 'NetworkNode', mappings: Dict['NetworkNode', 'NetworkNode']) -> Self:
        """Merge an another entity here, return mapping to replace entities"""
        mappings[entity] = self
        c_map = {c.name: c for c in self.children}
        for c in entity.children:
            self_c = c_map.get(c.name)
            if self_c:
                self_c.merge_in(c, mappings)
            else:
                c.parent = self
                self.children.append(c)
        return self

    def create_service(self, address: EndpointAddress) -> 'Service':
        """Create a child service"""
        raise NotImplementedError()

    def free_child_name(self, name_base: str) -> str:
        """Get free child name, rename existing if required"""
        names = {c.name: c for c in self.children}
        c = 1
        n = f"{name_base} {c}"
        if name_base in names:
            # reusing name base, add numbers to _all_ of them
            old = names[name_base]
            old.name = n
            names[n] = old  # 2nd reference to the host
        elif n not in names:
            return name_base  # name is free
        while n in names:
            c += 1
            n = f"{name_base} {c}"
        return n

    def get_entity(self, name: str) -> Optional['Addressable']:
        """Get addressable entity by name, do not create new one"""
        for c in self.children:
            if c.name == name and isinstance(c, Addressable):
                return c
        return None

    def get_endpoint(self, address: AnyAddress) -> 'Addressable':
        """Get or create a new endpoint, service or host"""
        raise NotImplementedError()

    def add_component(self, component: 'NodeComponent') -> 'NodeComponent':
        """Add new component"""
        self.components.append(component)
        return component

    def addressable(self, func: Callable[['Addressable'], T]) -> Optional[T]:
        """Call and return function for addressable entity, if this is one"""
        return func(self) if isinstance(self, Addressable) else None

    def is_addressable(self) -> bool:
        """Is addressable entity?"""
        return isinstance(self, Addressable)

    def is_host(self) -> bool:
        return isinstance(self, Host)

    def is_host_reachable(self) -> bool:
        return isinstance(self, Host)  # NOTE: Also IoTSystem is

    def reset(self):
        """Reset model"""
        super().reset()
        if not self.is_original():
            self.status = Status.PLACEHOLDER
        for c in self.children:
            c.reset()
        for s in self.components:
            s.reset()
        # NOTE: Addressable does not override, thus addresses remain to that the Entities are reused


class Addressable(NetworkNode):
    """Addressable entity"""
    def __init__(self, name: str):
        super().__init__(name)
        self.parent: Optional[NetworkNode] = None
        self.addresses: Set[AnyAddress] = set()
        self.any_host = False  # can be one or many hosts

    def create_service(self, address: EndpointAddress) -> 'Service':
        s = Service(Service.make_name(f"{address.protocol.value.upper()}", address.port), self)
        s.addresses.add(address.change_host(Addresses.ANY))
        if self.status == Status.EXTERNAL:
            s.status = Status.EXTERNAL  # only external propagates, otherwise unexpected
        s.external_activity = self.external_activity
        self.children.append(s)
        return s

    def is_global(self) -> bool:
        if self.parent and self.parent.is_global():
            return True
        sm = self.get_system()
        return len(self.addresses) > 0 and any(sm.is_external(a) for a in self.addresses)

    def is_multicast(self) -> bool:
        if self.parent and self.parent.is_multicast():
            return True
        return self.addresses and any(a.is_multicast() for a in self.addresses)

    def get_addresses(self, ads: Set[AnyAddress] = None) -> Set[AnyAddress]:
        """Get all addresses"""
        ads = set() if ads is None else ads
        p = self.parent
        for a in self.addresses:
            if a.is_wildcard() and isinstance(p, Addressable):
                for pa in p.addresses:
                    ads.add(a.change_host(pa.get_host()))
            else:
                ads.add(a)
        for c in self.children:
            c.get_addresses(ads)
        return ads

    def get_endpoint(self, address: AnyAddress) -> 'Addressable':
        for c in self.children:
            if address in c.addresses:
                return c
            for a in c.addresses:
                if a.is_wildcard():
                    ac = a.change_host(address.get_host())
                    if ac == address:
                        return c
        assert isinstance(address, EndpointAddress), "Bad address for service"
        return self.create_service(address)

    def new_connection(self, connection: Connection, flow: Flow, target: bool):
        """New connection with this entity either as source or target"""

    def set_seen_now(self, changes: List[Entity] = None) -> bool:
        r = super().set_seen_now(changes)
        if r and self.parent and not isinstance(self.parent, IoTSystem):
            # propagate to parent, it is also seen now
            self.parent.set_seen_now(changes)
        return r

    def get_system(self) -> 'IoTSystem':
        return self.parent.get_system()

    def get_parent_host(self) -> 'Host':
        """Get the parent host"""
        return self.parent.addressable(lambda p: p.get_parent_host())


class Host(Addressable):
    """A host"""
    def __init__(self, parent: 'IoTSystem', name: str):
        super().__init__(name)
        self.concept_name = "node"
        self.parent = parent
        self.visual = True
        self.ignore_name_requests: Set[DNSName] = set()
        self.connections: List[Connection] = []  # connections initiated here

    def get_connections(self, relevant_only=True) -> List[Connection]:
        """Get relevant connections"""
        cs = []
        for c in self.connections:
            if not relevant_only or c.is_relevant(ignore_ends=True):
                cs.append(c)
        cs.extend(super().get_connections(relevant_only))
        return cs

    def get_parent_host(self) -> 'Host':
        return self

    def learn_address_pair(self, hw: HWAddress, ip: IPAddress) -> bool:
        """Learn local address pair"""
        if not self.addresses:
            return False  # 'Any' target do not
        if hw.is_null():
            return False  # Null is not real address
        if not self.get_system().is_external(ip) and not ip.is_multicast() and not ip.is_null():
            # this should be unique address for me
            if ip not in self.addresses or hw not in self.addresses:
                self.addresses.add(ip)
                self.addresses.add(hw)
                return True
        return False

    def get_verdict(self, cache: Dict[Entity, Verdict]) -> Verdict:
        if self in cache:
            return cache[self]
        v = [super().get_verdict(cache)]
        for c in self.connections:
            if c.is_relevant():
                v.append(c.get_verdict(cache))
        rv = Verdict.aggregate(*v)
        cache[self] = rv
        return rv


class Service(Addressable):
    """A service"""
    def __init__(self, name: str, parent: Addressable):
        super().__init__(name)
        self.concept_name = "service"
        self.parent = parent
        self.protocol: Optional[Protocol] = None  # known protocol
        self.host_type = parent.host_type
        self.con_type = ConnectionType.UNKNOWN
        self.authentication = False            # Now a flag, an object later?
        self.client_side = False               # client side "service" (DHCP)
        self.reply_from_other_address = False  # reply comes from other port (DHCP)

    @classmethod
    def make_name(cls, service_name: str, port=-1):
        """Make service name"""
        if not service_name:
            return f"{port}" if port >= 0 else "???"
        return f"{service_name}:{port}" if port >= 0 else service_name

    @classmethod
    def is_authentication(cls, entity: Entity) -> Optional[bool]:
        """Get authentication flag for services or none"""
        return entity.authentication if isinstance(entity, Service) else None

    def long_name(self):
        if self.parent.name != self.name:
            return f"{self.parent.name} {self.name}"
        return self.name

    def is_tcp_service(self):
        """Is a TCP-based service"""
        for a in self.addresses:
            app = a.get_protocol_port()
            if app and app[0] == Protocol.TCP:
                return True
        return False

    def is_encrypted(self) -> bool:
        """Is an encrypted service?"""
        return self.protocol in {Protocol.TLS, Protocol.SSH}

    def __repr__(self):
        return f"{self.status_string()} {self.parent.long_name()} {self.name}"


class IoTSystem(NetworkNode):
    """An IoT system"""
    def __init__(self, name="IoT system"):
        super().__init__(name)
        self.concept_name = "system"
        self.status = Status.EXPECTED
        # network mask(s)
        self.ip_networks = [ipaddress.ip_network("192.168.0.0/16")]  # reasonable default
        # online resources
        self.online_resources: Dict[str, str] = {}
        # original entities and connections
        self.originals: Set[Entity] = {self}
        # consumer for specific message types
        self.message_listeners: Dict[Addressable, Protocol] = {}
        # change listener
        self.model_listeners: List[ModelListener] = []

        # observed connections and replies
        self.connections: Dict[Tuple[AnyAddress, AnyAddress], Connection] = {}

    # NOTE: get_children() does not return connections

    def get_children(self) -> Iterable['Entity']:
        cs = self.get_connections()
        return itertools.chain(self.children, self.components, cs)

    def iterate_all(self) -> Iterator[Entity]:
        yield from super().iterate_all()
        for c in self.get_connections():
            if c.status != Status.PLACEHOLDER:
                yield c

    def is_host_reachable(self) -> bool:
        return True

    def is_external(self, address: AnyAddress) -> bool:
        """Is an external network address?"""
        h = address.get_host()
        if h.is_global():
            return True
        if h.is_multicast() or h.is_null() or not isinstance(h, IPAddress):
            return False
        # FIXME: How it works for IPv6?
        for m in self.ip_networks:
            if h.data in m:
                return False
        return True

    def learn_named_address(self, name: DNSName, address: Optional[AnyAddress]) -> Host:
        """Learn DNS named addresses"""
        # check for reverse DNS
        if name.name.endswith(".arpa") and len(name.name) > 5:
            nn = name.name[:-5]
            if nn.endswith(".in-addr") and len(nn) > 8:
                address = IPAddress.new(nn[:-8])
            elif nn.endswith(".ip6") and len(nn) > 4:
                nn = nn[:-4].replace(".", "")[::-1]
                nn = ":".join(re.findall("....", nn))
                address = IPAddress.new(nn)
            else:
                # E.g. _dns.resolver.arpa - leave as name!
                address = None
            if address:
                add = self.get_endpoint(address)
                assert isinstance(add, Host)
                return add

        # find relevant hosts
        named = None
        by_ip = []
        for h in self.get_hosts():
            if name in h.addresses:
                named = h
            elif address and address in h.addresses:
                by_ip.append(h)
        assert len(by_ip) < 2, f"Multiple hosts with address {address}"
        add = by_ip[0] if by_ip else None

        if not named and add:
            # just use the addressed
            add.addresses.add(name)
            # perhaps rename?
            pri = Addresses.get_prioritized(add.addresses)
            if not isinstance(pri, DNSName) and add.name == f"{pri}":
                # host named after IP-address, update to match DNS name
                nn = f"{pri}"
                if nn != add.name:
                    add.name = self.free_child_name(nn)
            return add

        if named is None:
            named = self.get_endpoint(name)

        if not add:
            # just use the named
            if address:
                named.addresses.add(address)
            return named

        if len(named.addresses) == 1:
            # named host has no IP addresses, remove it and use the other
            self.children.remove(named)
            add.addresses.add(name)
            return add

        # IP address shared by two hosts, use the latest as things change between captures
        add.addresses.remove(address)
        named.addresses.add(address)
        return named

    def learn_ip_address(self, host: Host, ip_address: IPAddress):
        """Learn IP address of a host. Remove the IP address from other hosts, if any"""
        pri = Addresses.get_prioritized(host.addresses)
        host.addresses.add(ip_address)
        if host.name == f"{pri}":
            # host named after address, update
            nn = f"{Addresses.get_prioritized(host.addresses)}"
            if nn != host.name:
                host.name = self.free_child_name(nn)
        self.call_listeners(lambda ln: ln.address_change(host))

        for h in self.get_hosts():
            if h != host:
                h.addresses.discard(ip_address)
                self.call_listeners(lambda ln: ln.address_change(h))  # pylint: disable=cell-var-from-loop

    def get_system(self) -> 'IoTSystem':
        return self

    def get_endpoint(self, address: AnyAddress) -> Addressable:
        """Get or create a new endpoint, service or host"""
        h_add = address.get_host()
        for e in self.children:
            if h_add in e.addresses:
                if isinstance(address, EndpointAddress):
                    e = e.get_endpoint(address) or e
                break
        else:
            # create new host and possibly service
            e = Host(self, f"{h_add}")
            if h_add.is_multicast():
                e.host_type = HostType.ADMINISTRATIVE
            else:
                e.host_type = HostType.REMOTE if self.is_external(h_add) else HostType.GENERIC
            e.description = "Unexpected host"
            e.addresses.add(h_add)
            e.external_activity = ExternalActivity.UNLIMITED  # we know nothing about its behavior
            self.children.append(e)
        if isinstance(address, EndpointAddress) and e.is_host():
            e = e.create_service(address)
        return e

    def new_connection(self, source: Tuple[Addressable, AnyAddress],
                       target: Tuple[Addressable, AnyAddress]) -> Connection:
        """Create a new connection"""
        send = source[0]
        tend = target[0]
        c = Connection(send, tend)
        send.get_parent_host().connections.append(c)
        if isinstance(target, Service):
            c.con_type = target.con_type
        # Connection not added to target until it has replied
        self.connections[source[1], target[1]] = c
        return c

    def get_addresses(self) -> Set[AnyAddress]:
        """Get all addresses"""
        ads = set()
        for c in self.children:
            c.get_addresses(ads)
        return ads

    def create_service(self, address: EndpointAddress) -> Service:
        return NotImplementedError()

    def reset(self):
        super().reset()
        for h in self.get_hosts():
            for c in h.connections:
                c.reset_connection(self)
        self.connections.clear()

    def call_listeners(self, fun: Callable[['ModelListener'], Any]):
        """Call model listeners"""
        for ln in self.model_listeners:
            fun(ln)

    def parse_url(self, url: str) -> Tuple[Service, str]:
        """Parse URL and return the service and path"""
        u = urlparse(url)
        proto = Protocol.TLS if u.scheme == "https" else Protocol.get_protocol(u.scheme)
        if proto is None:
            raise ValueError(f"Unsupported scheme: {u.scheme}")
        if u.port is None:
            port = 80 if proto == Protocol.HTTP else 443
        else:
            port = u.port
        sadd = EndpointAddress(DNSName.name_or_ip(u.hostname), Protocol.TCP, port)
        se = self.get_endpoint(sadd)
        assert isinstance(se, Service)
        path = u.path
        if path.startswith("/"):
            path = path[1:]
        if path.endswith("/"):
            path = path[0:-1]
        return se, path

    def __repr__(self):
        s = [self.long_name()]
        for h in self.get_hosts():
            s.append(f"{h.status.value} {h.name} {sorted(h.addresses)}")
        for conn in self.connections.values():
            s.append(f"{conn.status} {conn}")
        return "\n".join(s)


class ModelListener:
    """Listener for model changes"""
    def connection_change(self, connection: Connection):
        """Connection created or changed"""

    def host_change(self, host: Host):
        """Host created or changed"""

    def address_change(self, host: Host):
        """Host addresses have changed"""

    def service_change(self, service: Service):
        """Service created or changed"""

    def property_change(self, entity: Entity, value: Tuple[PropertyKey, Any]):
        """Property changed. Not all changes create events, just the 'important' ones"""


class EvidenceNetworkSource(EvidenceSource):
    """Evidence source with network data"""
    def __init__(self, name: str, base_ref="", label="",
                 address_map: Dict[AnyAddress, Addressable] = None,
                 activity_map: Dict[NetworkNode, ExternalActivity] = None):
        super().__init__(name, base_ref, label)
        self.address_map = address_map or {}
        self.activity_map = activity_map or {}

    def rename(self, name: Optional[str] = None, base_ref: Optional[str] = None,
               label: Optional[str] = None) -> Self:
        s = EvidenceNetworkSource(
            self.name if name is None else name,
            self.base_ref if base_ref is None else base_ref,
            self.label if label is None else label,
            self.address_map, self.activity_map)
        s.model_override = self.model_override
        return s

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict:
        r = super().get_data_json(id_resolver)
        if self.address_map:
            r["address_map"] = {k.get_parseable_value(): id_resolver(v) for k, v in self.address_map.items()}
        if self.activity_map:
            # JSON does not allow integer keys
            r["activity_map"] = [[id_resolver(k), v.value] for k, v in self.activity_map.items()]
        return r

    def decode_data_json(self, data: Dict, id_resolver: Callable[[Any], Any]) -> 'EvidenceNetworkSource':
        """Parse data from JSON"""
        for a, e in data.get("address_map", {}).items():
            ent = id_resolver(e)
            self.address_map[Addresses.parse_endpoint(a)] = ent
        for n, a in data.get("activity_map", {}):
            ent = id_resolver(n)
            self.activity_map[ent] = ExternalActivity(a)
        return self
