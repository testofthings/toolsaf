"""Connection and endpoint matching"""

from typing import Any, Dict, List, Optional, Set, Tuple, cast

from toolsaf.core.address_ranges import MulticastTarget
from toolsaf.common.address import AddressAtNetwork, Addresses, AnyAddress, EndpointAddress, EntityTag, \
    Network, Protocol
from toolsaf.common.basics import Status
from toolsaf.common.traffic import Flow, IPFlow
from toolsaf.core.model import Addressable, Connection, Host, IoTSystem, Service

class MatcherEngine:
    """Matcher engine for matching connections and endpoints"""
    def __init__(self, system: IoTSystem):
        self.system = system
        self.endpoints: Dict[Addressable, AddressClue] = {}
        self.addresses: Dict[AddressAtNetwork, List[AddressClue]] = {}
        self.wildcard_hosts: List[AddressClue] = []
        self.connections: Dict[Connection, ConnectionClue] = {}

    def find_host(self, address: AnyAddress) -> Optional[Host]:
        """Find host by address"""
        host = address.get_host()
        networks = self.system.get_networks_for(host)
        for net in networks:
            addr_net = AddressAtNetwork(host, net)
            clues = self.addresses.get(addr_net, [])
            for clue in clues:
                if isinstance(clue.entity, Host):
                    return clue.entity
        return None

    def add_host(self, host: Addressable) -> None:
        """Add host and its services to matching engine"""
        self.add_addressable(host.get_parent_host())

    def add_address_mapping(self, address: AnyAddress, entity: Addressable) -> None:
        """Add address mapping for entity beyond entity's own addresses"""
        nets = entity.get_networks_for(address) or [self.system.get_default_network()]
        for net in nets:
            net_add = AddressAtNetwork(address, net)
            clue = self.add_addressable(entity)
            clue.addresses.add(net_add)
            # clear old mappings for the address
            self.addresses[net_add] = [clue]

        if not entity.any_host:
            # remove from wildcard hosts, if there
            self.wildcard_hosts = [wc for wc in self.wildcard_hosts if wc.entity != entity or wc.multicast_source]

    def update_host(self, host: Addressable) -> None:
        """Notify engine of address update for host"""
        clue = self.endpoints.get(host)
        if not clue:
            self.add_addressable(host)
            return
        # delete removed addresses and add new ones
        new_set: Set[AddressAtNetwork] = set()
        additions = False
        for address in host.addresses:
            if isinstance(address, EntityTag):
                continue  # skip tags
            for net in host.get_networks_for(address):
                addr_net = AddressAtNetwork(address, net)
                if addr_net not in clue.addresses:
                    # new address
                    clue.addresses.add(addr_net)
                    clue.soft_addresses.add(addr_net)
                    # override old mappings for the address
                    for old_clue in self.addresses.get(addr_net, ()):
                        if old_clue != clue:
                            old_clue.addresses.remove(addr_net)
                    self.addresses[addr_net] = [clue]
                    additions = True
                new_set.add(addr_net)
            for addr_net in list(clue.addresses):
                if addr_net not in new_set and addr_net in clue.soft_addresses:
                    # removed address
                    clue.addresses.remove(addr_net)
                    clues = self.addresses.get(addr_net)
                    if clues:
                        clues.remove(clue)
                        if not clues:
                            del self.addresses[addr_net]

        if additions and not host.any_host and not clue.addresses:
            # remove from wildcard hosts, if there, do not re-add
            self.wildcard_hosts = [wc for wc in self.wildcard_hosts if wc.entity != host or wc.multicast_source]

    def add_connection(self, connection: Connection) -> Connection:
        """Add connection to matching engine"""
        clue = self.connections.get(connection)
        if clue:
            return connection  # already added
        clue = ConnectionClue(connection)
        self.connections[connection] = clue

        self.add_addressable(connection.source)
        self.add_addressable(connection.target)

        source_end = self.endpoints.get(connection.source)
        assert source_end is not None, "Endpoint clue missing for connection source"
        source_end.source_for.append(clue)

        target_end = self.endpoints.get(connection.target)
        assert target_end is not None, "Endpoint clue missing for connection target"
        target_end.target_for.append(clue)

        return connection

    def remove_connection(self, connection: Connection) -> None:
        """Remove connection from matching engine"""
        clue = self.connections.pop(connection, None)
        if not clue:
            return  # not found
        source_end = self.endpoints.get(connection.source)
        if source_end:
            source_end.source_for.remove(clue)
        target_end = self.endpoints.get(connection.target)
        if target_end:
            target_end.target_for.remove(clue)

    def add_addressable(self, entity: Addressable) -> 'AddressClue':
        """Add addressable host or service"""
        clue = self.endpoints.get(entity)
        if clue:
            return clue
        clue = AddressClue(entity)
        self.endpoints[entity] = clue

        parent = entity.get_parent_host()
        if parent != entity:
            # ensure parent host is also added
            self.add_addressable(parent)

        addresses = False
        for add in entity.addresses:
            for net in entity.get_networks_for(add):
                match add:
                    case EntityTag():
                        continue  # skip tags
                    case EndpointAddress():
                        ep_key = add.get_protocol_port()
                        assert ep_key is not None, "Endpoint address without protocol/port"
                        clue.endpoints.add(ep_key)
                        h_addr = add.get_host()
                        host = entity.get_parent_host()
                        if h_addr == Addresses.ANY and host != entity:
                            # add endpoint to parent host
                            host_clue = self.add_addressable(host)
                            host_clue.services[ep_key] = clue
                        else:
                            # new address for this entity
                            add_net = AddressAtNetwork(h_addr, net)
                            self.addresses.setdefault(add_net, []).append(clue)
                    case _:
                        add_net = AddressAtNetwork(add, net)
                        self.addresses.setdefault(add_net, []).append(clue)
                        clue.addresses.add(add_net)
                addresses = True

        if isinstance(entity, Service) and entity.multicast_target:
            # service is listening on multicast or broadcast address
            for net in entity.networks or [self.system.get_default_network()]:
                clue.multicast_source[net] = entity.multicast_target

        if entity.any_host or not addresses or clue.multicast_source:
            # no addresses defined, add wildcard clue
            self.wildcard_hosts.append(clue)

        # ensure services are also added
        for c in entity.children:
            if isinstance(c, Service):
                self.add_addressable(c)

        return clue

    def __repr__(self) -> str:
        r = []
        for addr, clues in self.addresses.items():
            for clue in clues:
                r.append(f"{addr} | {clue}")
        for clue in self.wildcard_hosts:
            r.append(f"| {clue}")
        # for conn in self.connections.values():
        #     r.append(f"{conn}")
        return "\n".join(r)


class MatchingState:
    """Matching state"""
    def __init__(self, engine: MatcherEngine) -> None:
        self.engine = engine
        self.values: Dict[Any, StateValue] = {}

    def get_if(self, item: Any) -> Optional['StateValue']:
        """Get deduction value for item"""
        return self.values.get(item)

    def get(self, item: Any) -> 'StateValue':
        """Get deduction value for item"""
        return self.values.setdefault(item, StateValue())

    def get_all_sorted(self) -> List[Tuple[Any, 'StateValue']]:
        """Get all deduction values sorted by weight"""
        return sorted(self.values.items(), key=lambda kv: -kv[1].weight)

    def __repr__(self) -> str:
        r = []
        for key, value in sorted(self.values.items(), key=lambda kv: -kv[1].weight):
            r.append(f"{value.weight:<3} {key} # {value.reference}")
        return "\n".join(r)

class StateValue:
    """Matching state value"""
    def __init__(self) -> None:
        self.weight: int = 0
        self.reference: Optional[Any] = None

    def __repr__(self) -> str:
        return f"{self.weight} # {self.reference}"


class AddressClue:
    """Address clue"""
    def __init__(self, entity: Addressable) -> None:
        self.entity = entity
        self.services: Dict[Tuple[Protocol, int], AddressClue] = {}
        self.addresses: Set[AddressAtNetwork] = set()      # effective addresses
        self.soft_addresses: Set[AddressAtNetwork] = set() # addresses added/removed as we go
        self.endpoints: Set[Tuple[Protocol, int]] = set()  # only for services
        self.source_for: List[ConnectionClue] = []
        self.target_for: List[ConnectionClue] = []
        self.multicast_source: Dict[Network, MulticastTarget] = {}

    def update(self, state: MatchingState, address: AddressAtNetwork, protocol: Protocol, port: int,
               multicast: bool = False, wildcard: bool = False) -> None:
        """Update state observing this host"""
        is_service = isinstance(self.entity, Service)
        ep_key = (protocol, port)
        if self.endpoints and ep_key not in self.endpoints:
            return  # this host/service does not have this endpoint

        multicast_source = self.multicast_source.get(address.network)
        multicast_match = False
        if multicast_source:
            assert is_service, "Multicast source only for services"
            if not multicast_source.is_match(address.address):
                return  # multicast address does not match
            multicast_match = True

        status = self.entity.status
        match status:
            case Status.EXPECTED if is_service and not wildcard:
                w = 128 # expected address + service match
            case Status.EXPECTED if is_service and multicast_match:
                w = 128 # expected multicast address + service match
            case Status.EXPECTED if not wildcard:
                w = 64  # expected address match
            case Status.EXPECTED if is_service:
                w = 32  # expected service match
            case Status.EXTERNAL if is_service:
                w = 16  # external service
            case Status.EXPECTED:
                w = 8   # expected wildcard match
            case Status.EXTERNAL:
                w = 4   # external wildcard match
            case Status.UNEXPECTED if is_service:
                w = 2   # unexpected service
            case _:
                w = 1  # unexpected address or wildcard
        if is_service or not wildcard:
            # connections from/to wildcard host only with port/protocol
            value = state.get(self.entity)
            if w > value.weight:
                value.weight = w
                value.reference = address
        for conn in self.source_for:
            conn.update(state, w, source=address)
        for conn in self.target_for:
            conn.update(state, w, target=address)
        # check services
        service_clue = self.services.get(ep_key)
        if service_clue:
            service_clue.update(state, address, protocol, port, multicast, wildcard=wildcard)

    def __repr__(self) -> str:
        r = [f"{self.entity}"]
        for cc in self.source_for:
            r.append(f"  => {cc.connection.target.long_name()}")
        for cc in self.target_for:
            r.append(f"  <= {cc.connection.source.long_name()}")
        for service in self.services.values():
            r.append(f"  {service.entity}")
            for cc in service.source_for:
                r.append(f"    => {cc.connection.target.long_name()}")
            for cc in service.target_for:
                r.append(f"    <= {cc.connection.source.long_name()}")
        return "\n".join(r)


class ConnectionClue:
    """Connection clue"""
    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    def update(self, state: MatchingState, weight: int,
               source: Optional[AddressAtNetwork] = None, target: Optional[AddressAtNetwork] = None) -> None:
        """Update state observing this connection"""
        end_key = (target is not None, self.connection)
        value = state.get(end_key)
        if weight > value.weight:
            value.weight = weight
            value.reference = source or target
        sum_value = state.get(self.connection)
        ss, ts = state.get((True, self.connection)), state.get((False, self.connection))
        sum_value.weight = ss.weight + ts.weight

    def __repr__(self) -> str:
        return f"{self.connection.long_name()}"


class FlowMatcher:
    """Flow matcher"""
    def __init__(self, engine: MatcherEngine, flow: Flow) -> None:
        self.engine = engine
        self.system = engine.system
        self.flow = flow
        self.sources = MatchingState(engine)
        self.targets = MatchingState(engine)
        match flow:
            case IPFlow():
                net = flow.network or engine.system.get_default_network()
                # find source ends
                # - with external IP, HW is the local router
                # - with HW matching to endpoint, ignore IP, unless multicast/broadcast
                is_multicast = flow.source[0].is_multicast()
                use_ip = (AddressAtNetwork(flow.source[1], net) in engine.addresses or \
                    engine.system.is_external(flow.source[1])) or is_multicast
                use_hw = not use_ip
                if use_ip:
                    # match by IP address
                    self.map_address(self.sources, AddressAtNetwork(flow.source[1], net), flow.protocol, flow.source[2],
                                     multicast=is_multicast)
                if use_hw:
                    # match by HW address
                    self.map_address(self.sources, AddressAtNetwork(flow.source[0], net), flow.protocol, flow.source[2])

                # update by target
                is_multicast = flow.target[0].is_multicast()
                use_ip = (AddressAtNetwork(flow.target[1], net) in engine.addresses or \
                    engine.system.is_external(flow.target[1])) or is_multicast
                use_hw = not use_ip
                if use_ip:
                    self.map_address(self.targets, AddressAtNetwork(flow.target[1], net), flow.protocol, flow.target[2],
                                     multicast=is_multicast)
                if use_hw:
                    self.map_address(self.targets, AddressAtNetwork(flow.target[0], net), flow.protocol, flow.target[2])
            case _:
                net = flow.network or engine.system.get_default_network()
                # update by source
                for addr in flow.stack(target=False):
                    self.map_address(self.sources, AddressAtNetwork(addr, net), flow.protocol, flow.port(False))
                # update by target
                for addr in flow.stack(target=True):
                    self.map_address(self.targets, AddressAtNetwork(addr, net), flow.protocol, flow.port(True))
        # resolved connection
        self.connection: Optional[Connection | Tuple[Optional[Addressable], Optional[Addressable]]] = None
        self.reverse: bool = False
        self.end_addresses: Optional[Tuple[Optional[AnyAddress], Optional[AnyAddress]]] = None

    def map_address(self, state: MatchingState, address: AddressAtNetwork, protocol: Protocol, port: int,
                    multicast: bool = False) -> None:
        """Map address to state"""
        # 1. Map by address
        clues = self.engine.addresses.get(address)
        for clue in clues or ():
            clue.update(state, address, protocol, port)
        # 2. Map the wildcard hosts
        for clue in self.engine.wildcard_hosts:
            clue.update(state, address, protocol, port, multicast=multicast, wildcard=True)

    def get_connection(self) -> Connection | Tuple[Optional[Addressable], Optional[Addressable]]:
        """Get deduced connection for the flow, return endpoints if no connection matched"""
        if self.connection is not None:
            return self.connection

        source_items = self.sources.get_all_sorted()
        target_items = self.targets.get_all_sorted()

        # max. endpoint weight
        max_endpoint_weight = 0
        for key, value in source_items:
            if not isinstance(key, Connection):
                max_endpoint_weight = value.weight
                break
        for key, value in target_items:
            if not isinstance(key, Connection):
                if value.weight > max_endpoint_weight:
                    max_endpoint_weight = value.weight
                    break

        # find connection with largest weight
        conn: Optional[Connection] = None
        conn_weights: Dict[Connection, int] = {}
        ends: Optional[Tuple[AddressAtNetwork, AddressAtNetwork]] = None
        best_weight = 0
        reverse = False
        # listing by target_items gives preference to target matches, when weights are equal
        for key, _ in target_items:
            if not isinstance(key, Connection) or key in conn_weights:
                continue
            # request direction
            sv, tv = self.sources.get((False, key)), self.targets.get((True, key))
            weight = sv.weight + tv.weight if sv.weight > 0 and tv.weight > 0 else 0
            # reverse direction
            r_sv, r_tv = self.sources.get((True, key)), self.targets.get((False, key))
            r_weight = r_sv.weight + r_tv.weight if r_sv.weight > 0 and r_tv.weight > 0 else 0
            b_weight = conn_weights[key] = max(weight, r_weight)
            if key.status != Status.EXPECTED and b_weight < max_endpoint_weight:
                # best expected connection used despite endpoint weights
                # - an endpoint may not have any expected connections
                continue
            if b_weight <= best_weight:
                continue  # not better than current best
            best_weight = b_weight
            reverse = weight < r_weight
            if not reverse:
                ends = cast(Tuple[AddressAtNetwork, AddressAtNetwork], (sv.reference, tv.reference))
            else:
                ends = cast(Tuple[AddressAtNetwork, AddressAtNetwork], (r_tv.reference, r_sv.reference))
            conn = key

        if conn:
            self.connection = conn
            self.reverse = reverse
            assert ends
            self.end_addresses = ends[0].address, ends[1].address
            return conn

        # find endpoints with largest weights

        # find largest endpoint
        first_end: Optional[Addressable] = None
        first_addr: Optional[AddressAtNetwork] = None
        best_weight = 0
        for key, value in source_items + target_items:
            if not isinstance(key, Addressable) or value.weight <= best_weight:
                continue
            first_end = key
            first_addr = value.reference
            best_weight = value.weight

        if not first_end or not first_addr:
            # no endpoints found
            self.connection = None, None
            return self.connection

        source_set = set(list(self.flow.stack(target=False)))
        is_first_source = first_addr.address in source_set

        # find largest endpoint on opposite side
        second_end: Optional[Addressable] = None
        second_addr: Optional[AddressAtNetwork] = None
        best_weight = 0
        for key, value in source_items + target_items:
            if not isinstance(key, Addressable) or value.weight <= best_weight:
                continue
            net_addr = value.reference
            if not net_addr or not isinstance(net_addr, AddressAtNetwork):
                continue
            if (net_addr.address.get_host() in source_set) == is_first_source:
                continue  # same side as first end
            if key.get_parent_host() == first_end.get_parent_host():
                continue  # same host as first end, cannot connect to self
            second_end = key
            second_addr = net_addr
            best_weight = value.weight

        if is_first_source:
            self.end_addresses = (first_addr.address, second_addr.address if second_addr else None)
            self.connection = (first_end, second_end)
        else:
            self.connection = (second_end, first_end)
            self.end_addresses = (second_addr.address if second_addr else None, first_addr.address)
        return self.connection

    def get_host_addresses(self) -> Tuple[Optional[AnyAddress], Optional[AnyAddress]]:
        """Get connection end host addresses for the flow"""
        source_host, target_host = self.end_addresses if self.end_addresses else (None, None)
        source_address: Optional[AnyAddress] = None
        if source_host:
            source_address = EndpointAddress(source_host, self.flow.protocol, self.flow.port(self.reverse))
        target_address: Optional[AnyAddress] = None
        if target_host:
            target_address = EndpointAddress(target_host, self.flow.protocol, self.flow.port(not self.reverse))
        return source_address, target_address

    def __repr__(self) -> str:
        return f"{self.flow}\n{self.sources}\n---\n{self.targets}"
