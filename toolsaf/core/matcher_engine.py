"""Connection and endpoint matching"""

from typing import Any, Dict, List, Optional, Set, Tuple, cast

from toolsaf.common.address import AddressAtNetwork, Addresses, AnyAddress, EndpointAddress, EntityTag, Protocol
from toolsaf.common.traffic import Flow, IPFlow
from toolsaf.core.model import Addressable, Connection, Host, IoTSystem, Service

class Weights:
    """Clue weights"""
    ADDRESS = 100
    IP_ADDRESS = 101
    HW_ADDRESS = 102
    WILDCARD_ADDRESS = 99

    PROTOCOL_PORT = 10

class MatcherEngine:
    """Matcher engine for matching connections and endpoints"""
    def __init__(self, system: IoTSystem):
        self.system = system
        self.endpoints: Dict[Addressable, AddressClue] = {}
        self.addresses: Dict[AddressAtNetwork, List[AddressClue]] = {}
        self.wildcard_hosts: List[AddressClue] = []
        self.connections: Dict[Connection, ConnectionClue] = {}

    def find_host(self, address: Any) -> Optional[Host]:
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
        """Add host and it's services to matching engine"""
        self.add_addressable(host.get_parent_host())

    def add_address_mapping(self, address: AnyAddress, entity: Addressable) -> None:
        """Add address mapping for entity beyond entity's own addresses"""
        nets = entity.get_networks_for(address)
        assert len(nets) <= 1, "Unsupported multiple networks for address"
        net = nets[0] if nets else self.system.get_default_network()
        net_add = AddressAtNetwork(address, net)

        clue = self.add_addressable(entity)
        clue.addresses.add(net_add)
        # clear old mappings for the address
        self.addresses[net_add] = [clue]

    def update_host(self, host: Addressable) -> None:
        """Notify engine of address update for host"""
        clue = self.endpoints.get(host)
        if not clue:
            self.add_addressable(host)
            return
        # delete removed addresses and add new ones
        new_set: Set[AddressAtNetwork] = set()
        for address in host.addresses:
            if isinstance(address, EntityTag):
                continue  # skip tags
            net = host.get_networks_for(address)[0]
            addr_net = AddressAtNetwork(address, net)
            if addr_net not in clue.addresses:
                # new address
                clue.addresses.add(addr_net)
                # override old mappings for the address
                self.addresses[addr_net] = [clue]
            new_set.add(addr_net)
        for addr_net in list(clue.addresses):
            if addr_net not in new_set:
                # removed address
                clue.addresses.remove(addr_net)
                clues = self.addresses.get(addr_net)
                if clues:
                    clues.remove(clue)
                    if not clues:
                        del self.addresses[addr_net]

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
        # FIXME: Make it impossible to have multiple networks for one address and entity
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
            add_nets = entity.get_networks_for(add)
            # FIXME: Make it impossible to have multiple networks for one address and entity
            assert len(add_nets) == 1, "Unsupported multiple networks for address"
            net = add_nets[0]
            match add:
                case EntityTag():
                    continue  # skip tags
                case EndpointAddress():
                    ep_key = add.get_protocol_port()
                    assert ep_key is not None, "Endpoint address without protocol/port"
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
        if not addresses:
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


class DeductionState:
    """Clue state"""
    def __init__(self, engine: MatcherEngine) -> None:
        self.engine = engine
        self.values: Dict[Any, DeductionValue] = {}

    def get_if(self, item: Any) -> Optional['DeductionValue']:
        """Get deduction value for item"""
        return self.values.get(item)

    def get(self, item: Any) -> 'DeductionValue':
        """Get deduction value for item"""
        return self.values.setdefault(item, DeductionValue())

    def get_all_sorted(self) -> List[Tuple[Any, 'DeductionValue']]:
        """Get all deduction values sorted by weight"""
        return sorted(self.values.items(), key=lambda kv: -kv[1].weight)

    def __repr__(self) -> str:
        r = []
        for key, value in sorted(self.values.items(), key=lambda kv: -kv[1].weight):
            r.append(f"{value.weight:<3} {key} # {value.reference}")
        return "\n".join(r)

class DeductionValue:
    """Deduction value"""
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
        self.addresses: Set[AddressAtNetwork] = set()
        self.source_for: List[ConnectionClue] = []
        self.target_for: List[ConnectionClue] = []

    def update(self, state: DeductionState, address: AddressAtNetwork, protocol: Protocol, port: int,
               wildcard: bool = False) -> None:
        """Update state observing this host"""
        is_service = isinstance(self.entity, Service)
        w = 1 if wildcard else (3 if is_service else 2)
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
        ep_key = (protocol, port)
        service_clue = self.services.get(ep_key)
        if service_clue:
            service_clue.update(state, address, protocol, port, wildcard)

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

    def update(self, state: DeductionState, weight: int,
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
        self.sources = DeductionState(engine)
        self.targets = DeductionState(engine)
        match flow:
            case IPFlow():
                net = flow.network or engine.system.get_default_network()
                # update by source
                if not self.system.is_external(flow.source[1]):
                    # external IP address - HW is local router
                    self.map_address(self.sources, AddressAtNetwork(flow.source[0], net), flow.protocol, flow.source[2])
                self.map_address(self.sources, AddressAtNetwork(flow.source[1], net), flow.protocol, flow.source[2])

                # update by target
                if not self.system.is_external(flow.target[1]):
                    # external IP address - HW is local router
                    self.map_address(self.targets, AddressAtNetwork(flow.target[0], net), flow.protocol, flow.target[2])
                self.map_address(self.targets, AddressAtNetwork(flow.target[1], net), flow.protocol, flow.target[2])
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

    def map_address(self, state: DeductionState, address: AddressAtNetwork, protocol: Protocol, port: int) -> None:
        """Map address to deduction state"""
        clues = self.engine.addresses.get(address)
        for clue in clues or ():
            clue.update(state, address, protocol, port)
        for clue in self.engine.wildcard_hosts:
            clue.update(state, address, protocol, port, wildcard=True)

    def get_connection(self) -> Connection | Tuple[Optional[Addressable], Optional[Addressable]]:
        """Get deduced connection for the flow, return endpoints if no connection matched"""
        if self.connection is not None:
            return self.connection

        source_items = self.sources.get_all_sorted()
        target_items = self.targets.get_all_sorted()

        # find connection with largest weight
        conn: Optional[Connection] = None
        best_weight = 0
        ends: Optional[Tuple[AddressAtNetwork, AddressAtNetwork]] = None
        reverse = False
        for key, _ in source_items:
            if not isinstance(key, Connection):
                continue
            # request direction
            sv, tv = self.sources.get((False, key)), self.targets.get((True, key))
            weight = sv.weight + tv.weight if sv.weight > 0 and tv.weight > 0 else 0
            # reverse direction
            r_sv, r_tv = self.sources.get((True, key)), self.targets.get((False, key))
            r_weight = r_sv.weight + r_tv.weight if r_sv.weight > 0 and r_tv.weight > 0 else 0
            if max(weight, r_weight) <= best_weight:
                continue  # not better than current best
            reverse = weight < r_weight
            if not reverse:
                best_weight = weight
                ends = cast(Tuple[AddressAtNetwork, AddressAtNetwork], (sv.reference, tv.reference))
            else:
                best_weight = r_weight
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
