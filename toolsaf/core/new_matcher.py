"""Connection and endpoint matching"""

from collections.abc import Set
import heapq
from typing import Dict, List, Optional, Self, Tuple

from toolsaf.common.address import AddressAtNetwork, AnyAddress, Network
from toolsaf.common.traffic import Flow, IPFlow
from toolsaf.core.model import Addressable, Connection, IoTSystem


class ConnectionEndpoint:
    """Connection endpoint, single address cannot be in multiple endpoints"""
    def __init__(self, entity: Addressable, addresses: Tuple[AddressAtNetwork, ...]) -> None:
        self.entity = entity
        self.addresses = addresses
        self.address_set = set(addresses)

    def __hash__(self) -> int:
        return self.entity.__hash__()

    def __eq__(self, other) -> bool:
        if not isinstance(other, ConnectionEndpoint):
            return NotImplemented
        return self.entity == other.entity


class ConnectionKey:
    """Connection key"""
    def __init__(self, source: ConnectionEndpoint, target: ConnectionEndpoint):
        self.source = source
        self.target = target
    
    def __hash__(self) -> int:
        return hash((self.source, self.target))

    def __eq__(self, other) -> bool:
        if not isinstance(other, ConnectionKey):
            return NotImplemented
        return self.source == other.source and self.target == other.target
    
    def __repr__(self):
        return f"{self.source} -> {self.target}"


class ConnectionMatcher:
    """Connection matcher"""
    def __init__(self, connection: Connection):
        self.connection = connection

    def match(self, connection: ConnectionKey) -> Optional[Connection]:
        """Check if connection matches and return it"""
        return self.connection


class MatchEngine:
    """Matching engine"""
    def __init__(self, system: IoTSystem):
        self.system = system
        # 1:n relation address:endpoint
        self.endpoints: Dict[AddressAtNetwork | Addressable, ConnectionEndpoint] = {}
        # connections
        self.connections: Dict[ConnectionKey, List[ConnectionMatcher]] = {}

    def add_entity(self, entity: Addressable) -> ConnectionEndpoint:
        """Add entity"""
        net = self.system.get_default_network()
        addresses = []
        # FIXME: This is not how address resolution should work
        for addr in entity.addresses:
            aan = AddressAtNetwork(addr, net)
            existing = self.endpoints.get(aan)
            if existing:
                raise ValueError(f"Address {aan} already assigned to {existing.entity}")
            addresses.append(aan)
        endpoint = ConnectionEndpoint(entity, tuple(addresses))
        self.endpoints[entity] = endpoint
        for addr in addresses:
            self.endpoints[addr] = endpoint
        return endpoint

    def add_connection(self, connection: Connection) -> Tuple[ConnectionKey, ConnectionMatcher]:
        """Add connection"""
        source = self.endpoints[connection.source]
        target = self.endpoints[connection.target]
        key = ConnectionKey(source, target)
        if key in self.connections:
            raise ValueError(f"Connection {key} already exists")
        matcher = ConnectionMatcher(connection)
        self.connections[key].append(matcher)
        return key, matcher


class MatrixAddress:
    """Cell in address matrix"""
    def __init__(self, priority: int, address: AddressAtNetwork):
        self.priority = priority
        self.address = address

    @classmethod
    def new(cls, proprity: int, address: AnyAddress, network: Network) -> 'MatrixAddress':
        """Create new matrix address"""
        return cls(proprity, AddressAtNetwork(address, network))


class ConnectionFinder:
    """Connection filder"""
    def __init__(self, engine: MatchEngine, flow: Flow):
        self.engine = engine
        self.flow = flow
        self.connections = engine.connections
        self.sources = self._flow_addresses(self.flow, target=False)
        self.targets = self._flow_addresses(self.flow, target=True)
        self.visited: Set[Tuple[int, int]] = set()
        # min-heap of (priority, source_index, target_index)
        self.visit: List[Tuple[int, int, int]] = []

    def find(self) -> Optional[Connection]:
        """Find connection for flow"""
        if not self.sources or not self.targets:
            return None
        
        # visit (0, 0) first
        heapq.heappush(self.visit, (0, 0, 0))

        while self.visit:
            # get source-target pair with lowest priority
            _, source_i, target_i = heapq.heappop(self.visit)
            source_addr, target_addr = self.sources[source_i], self.targets[target_i]
            source = self.engine.endpoints[source_addr.address]
            target = self.engine.endpoints[target_addr.address]

            # once key match, see if any matcher gives a connection
            key = ConnectionKey(source, target)
            match = self.connections.get(key) or []
            for matcher in match:
                conn = matcher.match(key)
                if conn:
                    return conn
            
            # no match, enqueue next possible addresses
            if source_i + 1 < len(self.sources):
                key_i = (source_i + 1, target_i)
                if key_i not in self.visited:
                    s, t = source_i + 1, target_i
                    priority = min(self.sources[s].priority, self.targets[t].priority)
                    heapq.heappush(self.visit, (priority, s, t))
            if target_i + 1 < len(self.targets):
                key_i = (source_i, target_i + 1)
                if key_i not in self.visited:
                    s, t = source_i, target_i + 1
                    priority = min(self.sources[s].priority, self.targets[t].priority)
                    heapq.heappush(self.visit, (priority, s, t))
        return None

    def _flow_addresses(self, flow: Flow, target: bool) -> Tuple[MatrixAddress, ...]:
        """Resolve matching addresses for a flow"""

        net = flow.network or self.engine.system.get_default_network()

        addresses = []
        if isinstance(flow, IPFlow):
            end = flow.target if target else flow.source
            if self.engine.system.is_external(end[1]):
                addresses.append(MatrixAddress.new(0, end[1], net))  # match by IP only (HW for gateway)
            else:
                addresses.extend(MatrixAddress.new(-i, e, net) for i, e in enumerate(end[0:2])) # HW and IP
        else:
            addresses.extend(MatrixAddress.new(-i, e, net) for i, e in enumerate(flow.stack(target)))

        # filter addresses without endpoints
        filtered = [addr for addr in addresses if addr.address in self.engine.endpoints]

        return tuple(filtered)

