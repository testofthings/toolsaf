"""Connection and endpoint matching"""

from typing import Any, Dict, List, Optional, Set, Tuple, Type, TypeVar

from toolsaf.common.address import AddressAtNetwork, Addresses, AnyAddress, EndpointAddress, EntityTag, \
    HWAddress, IPAddress
from toolsaf.common.traffic import Flow, IPFlow
from toolsaf.core.model import Addressable, Connection, Host, IoTSystem

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
        self.clues = ClueMap()
        self.addresses: Dict[Addressable, Set[AddressAtNetwork]] = {}
        self.wildcard_hosts: Set[Addressable] = set()

    def find_host(self, address: Any) -> Optional[Addressable]:
        """Find host by address"""
        host = address.get_host()
        networks = self.system.get_networks_for(host)
        for net in networks:
            addr_net = AddressAtNetwork(host, net)
            clues = self.clues.clues.get(addr_net, [])
            for clue in clues:
                if isinstance(clue.item, Addressable):
                    return clue.item
        return None

    def add_connection(self, connection: Connection) -> Connection:
        """Add connection to matching engine"""
        self.add_entity(connection.source)
        self.add_entity(connection.target)
        self.clues.add_clue(connection.source, 0, connection)
        self.clues.add_clue(connection.target, 0, connection)
        return connection

    def add_entity(self, entity: Addressable) -> None:
        """Add entity to matching engine"""
        if entity in self.addresses:
            return  # already added
        for addr in entity.addresses:
            self._add_address(addr, entity)
        parent = entity.get_parent_host()
        if parent != entity:
            self.add_entity(parent)
            self.clues.add_clue(parent, 0, entity)
        self._update_wildcard_hosts(entity)

    def add_host(self, host: Addressable) -> None:
        """Add host and it's services to matching engine"""
        self.add_entity(host)
        for c in host.children:
            if isinstance(c, Addressable):
                self.add_entity(c)

    def add_address_mapping(self, address: AnyAddress, entity: Addressable) -> None:
        """Add address mapping for entity beyond entity's own addresses"""
        nets = entity.get_networks_for(address)
        assert len(nets) <= 1, "Unsupported multiple networks for address"
        net = nets[0] if nets else self.system.get_default_network()
        net_add = AddressAtNetwork(address, net)

        addresses = self.addresses.get(entity, set())
        if net_add in addresses:
            return  # already known

        old_mappings = self.clues.clues.get(net_add)
        if old_mappings:
            # we remove _all_ old mappings
            del self.clues.clues[net_add]

        self._add_address(address, entity)
        self._update_wildcard_hosts(entity)

    def update_host(self, host: Addressable) -> None:
        """Notify engine of address update for host"""
        new_net_addr: Set[AddressAtNetwork] = set()
        for addr in host.addresses:
            if isinstance(addr, EntityTag):
                continue
            nets = host.get_networks_for(addr)
            net = nets[0] if nets else self.system.get_default_network()
            net_add = AddressAtNetwork(addr, net)
            new_net_addr.add(net_add)
        removed = self.addresses.get(host, set()) - new_net_addr
        added = new_net_addr - self.addresses.get(host, set())
        for net_addr in removed.union(added):
            # remove all old mappings for the address, overriding any older mappings to other hosts, too
            if net_addr in self.clues.clues:
                del self.clues.clues[net_addr]
        for net_addr in added:
            self.add_address_mapping(net_addr.address, host)

        self._update_wildcard_hosts(host)

    def _add_address(self, address: AnyAddress, entity: Addressable) -> bool:
        """Add address clue for entity"""
        add_nets = entity.get_networks_for(address)
        # FIXME: Make it impossible to have multiple networks for one address and entity
        assert len(add_nets) == 1, "Unsupported multiple networks for address"
        net = add_nets[0]
        add_set = self.addresses.setdefault(entity, set())
        match address:
            case EntityTag():
                return  False # do not add clues for tags
            case EndpointAddress():
                h_addr = address.get_host()
                if h_addr != Addresses.ANY:
                    self._add_address(h_addr, entity)
                self.clues.add_clue(address.get_protocol_port(), Weights.PROTOCOL_PORT, entity)
            case HWAddress():
                add_net = AddressAtNetwork(address, net)
                add_set.add(add_net)
                self.clues.add_clue(add_net, Weights.HW_ADDRESS, entity)
            case IPAddress():
                add_net = AddressAtNetwork(address, net)
                add_set.add(add_net)
                self.clues.add_clue(add_net, Weights.IP_ADDRESS, entity)
            case _:
                add_net = AddressAtNetwork(address, net)
                add_set.add(add_net)
                self.clues.add_clue(add_net, Weights.ADDRESS, entity)
        return True

    def _update_wildcard_hosts(self, host: Addressable) -> None:
        # update wildcard hosts
        if not host.is_host():
            return
        if self.addresses.get(host):
            self.wildcard_hosts.discard(host)
        else:
            self.wildcard_hosts.add(host)

    def __repr__(self) -> str:
        return str(self.clues)


class ClueMap:
    """Clue map"""
    def __init__(self) -> None:
        self.clues: Dict[Any, List[Clue]] = {}

    def add_clue(self, reference: Any, weight: int, item: Any) -> None:
        """Add clue"""
        if reference is None or item is None:
            return
        clues = self.clues.setdefault(reference, [])
        new_clue = Clue(item, weight)
        if new_clue not in clues:
            clues.append(new_clue)

    def update_state(self, reference: Any, state: 'DeductionState', weight: int = 0,
                     from_value: Optional['StateValue'] = None) -> int:
        """Update deduction state with clues for reference"""
        value = state.get(reference, add=True)
        value.add_item(reference, weight)
        if from_value:
            value.references.update(from_value.references)
        clues = self.clues.get(reference, [])
        for clue in clues:
            clue_w = clue.weight + weight
            self.update_state(clue.item, state, weight=clue_w, from_value=value)
        return len(clues)

    def __repr__(self) -> str:
        r = []
        for key, clues in self.clues.items():
            r.append(f"{key}:")
            for clue in clues:
                r.append(f"=> {clue}")
        return "\n".join(r)


class Clue:
    """Clue"""
    def __init__(self, item: Any, weight: int) -> None:
        self.item = item
        self.weight = weight

    def __hash__(self) -> int:
        return hash((self.item, self.weight))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Clue):
            return False
        return self.item == other.item and self.weight == other.weight

    def __repr__(self) -> str:
        return f"{self.weight} | {self.item}"


class StateValue:
    """Deduction state value"""
    def __init__(self) -> None:
        self.references: Set[Any] = set()
        self.weight = 0

    def add_item(self, reference: Any, weight: int) -> None:
        """Add reference with weight"""
        self.references.add(reference)
        self.weight += weight

    def __add__(self, other: 'StateValue') -> 'StateValue':
        new_value = StateValue()
        new_value.weight = self.weight + other.weight
        new_value.references = self.references.union(other.references)
        return new_value

    def __repr__(self) -> str:
        return f"{self.weight}: {self.references}"

T = TypeVar('T')

class DeductionState:
    """Deduction state"""
    def __init__(self) -> None:
        self.state: Dict[Any, StateValue] = {}

    def get(self, item: Any, add: bool = False) -> StateValue:
        """Get value for item"""
        v = self.state.get(item)
        if v:
            return v
        v = StateValue()
        if add:
            self.state[item] = v
        return v

    def get_weight(self, item: Any) -> int:
        """Get weight for item"""
        v = self.state.get(item)
        return v.weight if v else 0

    def get_top_item(self, item_type: Type[T]) -> Optional[T]:
        """Get top item of given type"""
        best_item: Optional[T] = None
        best_weight = 0
        for item, value in self.state.items():
            if isinstance(item, item_type) and value.weight > best_weight:
                best_item = item
                best_weight = value.weight
        return best_item

    def __add__(self, other: 'DeductionState') -> 'DeductionState':
        new_state = DeductionState()
        new_state.state = other.state.copy()
        for item, value in self.state.items():
            n_value = new_state.state.get(item, StateValue())
            new_state.state[item] = n_value + value
        return new_state

    def __repr__(self) -> str:
        r = []
        state_sorted = sorted(self.state.items(), key=lambda x: x[1].weight, reverse=True)
        for item, weight in state_sorted:
            r.append(f"{item}: {weight}")
        return "\n".join(r)


class FlowMatcher:
    """Flow matcher"""
    def __init__(self, engine: MatcherEngine, flow: Flow) -> None:
        self.system = engine.system
        self.clues = engine.clues
        self.flow = flow
        self.sources = DeductionState()
        self.targets = DeductionState()
        match flow:
            case IPFlow():
                net = flow.network or engine.system.get_default_network()
                # update by source
                if self.system.is_external(flow.source[1]):
                    # external IP address - HW is local router
                    matches = self.clues.update_state(AddressAtNetwork(flow.source[1], net), self.sources)
                else:
                    matches = self.clues.update_state(AddressAtNetwork(flow.source[0], net), self.sources)
                    matches += self.clues.update_state(AddressAtNetwork(flow.source[1], net), self.sources)
                if not matches:
                    # no direct matches, promote wildcard hosts
                    for h in engine.wildcard_hosts:
                        self.clues.update_state(h, self.sources, Weights.WILDCARD_ADDRESS)
                self.clues.update_state((flow.protocol, flow.source[2]), self.sources)

                # update by target
                if self.system.is_external(flow.target[1]):
                    # external IP address - HW is local router
                    matches = self.clues.update_state(AddressAtNetwork(flow.target[1], net), self.targets)
                else:
                    matches = self.clues.update_state(AddressAtNetwork(flow.target[0], net), self.targets)
                    matches += self.clues.update_state(AddressAtNetwork(flow.target[1], net), self.targets)
                if not matches:
                    # no direct matches, promote wildcard hosts
                    for h in engine.wildcard_hosts:
                        self.clues.update_state(h, self.targets, Weights.WILDCARD_ADDRESS)
                self.clues.update_state((flow.protocol, flow.target[2]), self.targets)
            case _:
                raise NotImplementedError("Flow type not supported in matcher")
        # resolved connection
        self.connection: Optional[Connection | Tuple[Optional[Addressable], Optional[Addressable]]] = None
        self.reverse: bool = False
        self.end_addresses: Optional[Tuple[Optional[AnyAddress], Optional[AnyAddress]]] = None

    def get_connection(self) -> Connection | Tuple[Optional[Addressable], Optional[Addressable]]:
        """Get deduced connection for the flow, return endpoints if no connection matched"""
        if self.connection is not None:
            return self.connection

        # find connection with largest combined weight
        weights: Dict[Connection, StateValue] = {}
        conn: Optional[Connection] = None
        best: Optional[StateValue] = None
        for state in (self.sources, self.targets):
            for item, value in state.state.items():
                if isinstance(item, Connection):
                    bv = weights.setdefault(item, StateValue())
                    bv.weight += value.weight
                    bv.references.update(value.references)
                    if best is None or bv.weight > best.weight:
                        conn = item
                        best = bv
        if conn:
            source_weight = self.sources.get(conn.source).weight
            target_weight = self.targets.get(conn.target).weight
            target_weight_threshold = Weights.HW_ADDRESS
            if isinstance(conn.target, Host) and not conn.target.is_expected():
                # With service targets, also port match is required
                # But, with unexpected target and no service, only address match is enough
                target_weight_threshold -= 1
            if source_weight >= Weights.WILDCARD_ADDRESS and target_weight > target_weight_threshold:
                self.connection = conn
                return conn
            # hmm... perhaps reverse direction
            source_weight = self.sources.get(conn.target).weight
            target_weight = self.targets.get(conn.source).weight
            if source_weight > target_weight_threshold and target_weight >= Weights.WILDCARD_ADDRESS:
                self.connection = conn
                self.reverse = True
                return conn
        # no connection matched, return best effort endpoints
        source = self.sources.get_top_item(Addressable)
        source_weight = self.sources.get(source).weight if source else 0
        target = self.targets.get_top_item(Addressable)
        target_weight = self.targets.get(target).weight if target else 0
        self.connection = \
            (source if source_weight >= Weights.ADDRESS else None,
            target if target_weight >= Weights.ADDRESS else None)
        return self.connection

    def get_host_addresses(self) -> Tuple[Optional[AnyAddress], Optional[AnyAddress]]:
        """Get connection end host addresses for the flow"""
        conn = self.get_connection()
        source_end: Optional[Addressable]
        target_end: Optional[Addressable]
        if isinstance(conn, Connection):
            source_end = conn.source
            target_end = conn.target
        else:
            source_end, target_end = conn

        default_net = self.system.get_default_network()
        result: List[Optional[AnyAddress]] = [None, None]

        if not self.reverse:
            # flow direction matches connection direction
            source = source_end, self.sources, False
            target = target_end, self.targets, True
        else:
            # flow direction is reversed compared to connection direction
            source = source_end, self.targets, True
            target = target_end, self.sources, False

        for for_items in enumerate((source, target)):
            index, (end, state, i_target) = for_items
            if end is None:
                continue
            # check if address is listed as reference for the connection end -> return the address
            references = state.get(end).references
            net = self.flow.network or default_net
            ret_addr = None
            for addr in self.flow.stack(i_target):
                net_addr = AddressAtNetwork(addr, net)
                if net_addr in references:
                    ret_addr = addr
                    break
            if ret_addr is None:
                # default is used e.g. with wildcard match
                addr = self.flow.get_source_address() if not i_target else self.flow.get_target_address()
                ret_addr = addr
            if not ret_addr.get_protocol_port():
                port = self.flow.port(i_target)
                # we ensure endpoint address has protocol and port, even when matched by host address only
                ret_addr = EndpointAddress(ret_addr, self.flow.protocol, port)
            result[index] = ret_addr

        self.end_addresses = (result[0], result[1])
        return self.end_addresses

    def __repr__(self) -> str:
        return f"{self.sources}\n---\n{self.targets}"
