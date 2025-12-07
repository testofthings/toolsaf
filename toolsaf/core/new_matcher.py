"""Connection and endpoint matching"""

from typing import Any, Dict, List, Optional, Self, Tuple, Type, TypeVar

from toolsaf.common.address import AddressAtNetwork, Addresses, EndpointAddress, EntityTag, HWAddress, IPAddress
from toolsaf.common.traffic import Flow, IPFlow
from toolsaf.core.model import Addressable, Connection, IoTSystem

class Weights:
    """Clue weights"""
    ADDRESS = 100
    IP_ADDRESS = 101
    HW_ADDRESS = 102
    WILDCARD_ADDRESS = 99

    PROTOCOL_PORT = 10

class MatchEngine:
    """Matching engine"""
    def __init__(self, system: IoTSystem):
        self.system = system
        self.clues = ClueMap()

    def add_connection(self, connection: Connection) -> Connection:
        """Add connection to matching engine"""
        self.add_entity(connection.source)
        self.add_entity(connection.target)
        self.clues.add_clue(connection.source, 0, connection)
        self.clues.add_clue(connection.target, 0, connection)
        return connection

    def add_entity(self, entity: Addressable) -> None:
        """Add entity to matching engine"""
        if entity in self.clues.clues:
            return  # already added
        addresses = list(entity.addresses)
        parent = entity.get_parent_host()
        any_address = False
        for addr in addresses:
            net = entity.get_networks_for(addr)[0]
            match addr:
                case EntityTag():
                    continue  # do not add clues for tags
                case EndpointAddress():
                    h_addr = addr.get_host()
                    if h_addr != Addresses.ANY:
                        add_net = AddressAtNetwork(h_addr, net)
                        self.clues.add_clue(add_net, Weights.ADDRESS, entity)
                    self.clues.add_clue(addr.get_protocol_port(), Weights.PROTOCOL_PORT, entity)
                case HWAddress():
                    add_net = AddressAtNetwork(addr, net)
                    self.clues.add_clue(add_net, Weights.HW_ADDRESS, entity)
                case IPAddress():
                    add_net = AddressAtNetwork(addr, net)
                    self.clues.add_clue(add_net, Weights.IP_ADDRESS, entity)
                case _:
                    add_net = AddressAtNetwork(addr, net)
                    self.clues.add_clue(add_net, Weights.ADDRESS, entity)
            any_address = True
        if parent == entity and not any_address:
            # give this host edge for matching with unknown addresses
            self.clues.add_clue(Clue.WILDCARD_HOST, Weights.WILDCARD_ADDRESS, entity)
        if parent != entity:
            self.add_entity(parent)
            self.clues.add_clue(parent, 0, entity)

    def add_host(self, host: Addressable) -> None:
        """Add host and it's services to matching engine"""
        self.add_entity(host)
        for c in host.children:
            if isinstance(c, Addressable):
                self.add_entity(c)


class ClueMap:
    """Clue map"""
    def __init__(self, parent: Optional[Self] = None) -> None:
        self.clues: Dict[Any, List[Clue]] = {}
        self.parent = parent

    def add_clue(self, reference: Any, weight: int, item: Any) -> None:
        """Add clue"""
        if reference is None or item is None:
            return
        clues = self.clues.setdefault(reference, [])
        new_clue = Clue(item, weight)
        if new_clue not in clues:
            clues.append(new_clue)

    def update_state(self, reference: Any, state: 'DeductionState', weight: int = 0) -> int:
        """Update deduction state with clues for reference"""
        clues = self.clues.get(reference, [])
        for clue in clues:
            start_w = state.state.get(clue.item, 0)
            w = start_w + weight + clue.weight
            state.state[clue.item] = w
            self.update_state(clue.item, state, weight=w - start_w) # propagate weight increase
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

    # Item for wildcard host
    WILDCARD_HOST = "*"


T = TypeVar('T')

class DeductionState:
    """Deduction state"""
    def __init__(self) -> None:
        self.state: Dict[Any, int] = {}

    def get_top_item(self, item_type: Type[T]) -> Optional[T]:
        """Get top item of given type"""
        best_item: Optional[T] = None
        best_weight = 0
        for item, weight in self.state.items():
            if isinstance(item, item_type) and weight > best_weight:
                best_item = item
                best_weight = weight
        return best_item

    def __add__(self, other: 'DeductionState') -> 'DeductionState':
        new_state = DeductionState()
        new_state.state = other.state.copy()
        for item, weight in self.state.items():
            n_weight = new_state.state.get(item, 0)
            new_state.state[item] = n_weight + weight
        return new_state

    def __repr__(self) -> str:
        r = []
        for item, weight in self.state.items():
            r.append(f"{item}: {weight}")
        return "\n".join(r)


class FlowMatcher:
    """Flow matcher"""
    def __init__(self, engine: MatchEngine, flow: Flow) -> None:
        self.engine = engine
        self.clues = engine.clues
        self.flow = flow
        self.sources = DeductionState()
        self.targets = DeductionState()
        match flow:
            case IPFlow():
                net = flow.network or engine.system.get_default_network()
                # update by source
                matches = self.clues.update_state(AddressAtNetwork(flow.source[0], net), self.sources)
                matches += self.clues.update_state(AddressAtNetwork(flow.source[1], net), self.sources)
                if not matches:
                    # no direct matches, promote wildcard hosts
                    self.clues.update_state(Clue.WILDCARD_HOST, self.sources)
                self.clues.update_state((flow.protocol, flow.source[2]), self.sources)

                # update by target
                matches = self.clues.update_state(AddressAtNetwork(flow.target[0], net), self.targets)
                matches += self.clues.update_state(AddressAtNetwork(flow.target[1], net), self.targets)
                if not matches:
                    # no direct matches, promote wildcard hosts
                    self.clues.update_state(Clue.WILDCARD_HOST, self.targets)
                self.clues.update_state((flow.protocol, flow.target[2]), self.targets)


    def get_connection(self, _flow: Flow) -> Connection | Tuple[Optional[Addressable], Optional[Addressable]]:
        """Get deduced connection for flow, return endpoints if no connection matched"""

        # find connection with largest combined weight
        weights: Dict[Connection, int] = {}
        conn: Optional[Connection] = None
        best_weight = 0
        for state in (self.sources, self.targets):
            for item, weight in state.state.items():
                if isinstance(item, Connection):
                    n_weight = weights.get(item, 0) + weight
                    weights[item] = n_weight
                    if n_weight > best_weight:
                        conn = item
                        best_weight = n_weight
        if conn:
            source_weight = self.sources.state.get(conn.source, 0)
            target_weight = self.targets.state.get(conn.target, 0)
            if source_weight >= Weights.WILDCARD_ADDRESS and target_weight > Weights.HW_ADDRESS:
                return conn
            # hmm... perhaps reverse direction
            source_weight = self.sources.state.get(conn.target, 0)
            target_weight = self.targets.state.get(conn.source, 0)
            if source_weight > Weights.HW_ADDRESS and target_weight >= Weights.WILDCARD_ADDRESS:
                return conn
        # no connection matched, return best effort endpoints
        source = self.sources.get_top_item(Addressable)
        source_weight = self.sources.state.get(source, 0) if source else 0
        target = self.targets.get_top_item(Addressable)
        target_weight = self.targets.state.get(target, 0) if target else 0
        return (source if source_weight >= Weights.ADDRESS else None,
                target if target_weight >= Weights.ADDRESS else None)

    def __repr__(self) -> str:
        return f"{self.sources}\n---\n{self.targets}"
