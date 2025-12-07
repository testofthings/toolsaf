"""Connection and endpoint matching"""

from collections.abc import Set
from dataclasses import dataclass
import heapq
from typing import Any, Dict, Iterable, List, Optional, Self, Tuple, Type, TypeVar

from toolsaf.common.address import AddressAtNetwork, Addresses, AnyAddress, EndpointAddress, EntityTag, HWAddress, IPAddress
from toolsaf.common.traffic import Flow, IPFlow
from toolsaf.core.model import Addressable, Connection, IoTSystem


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
        # if parent != entity:
        #     addresses.extend(parent.addresses)
        for addr in addresses:
            match addr:
                case EntityTag():
                    pass  # do not add clues for tags
                case EndpointAddress():
                    h_addr = addr.get_host()
                    if h_addr != Addresses.ANY:
                        self.clues.add_clue(h_addr, 103, entity)
                    self.clues.add_clue(addr.get_protocol_port(), 10, entity)
                case HWAddress():
                    self.clues.add_clue(addr, 102, entity)
                case IPAddress():
                    self.clues.add_clue(addr, 101, entity)
                case _:
                    self.clues.add_clue(addr, 100, entity)
        if parent != entity:
            self.add_entity(parent)
            self.clues.add_clue(parent, 0, entity)

    def deduce_flow(self, flow: Flow) -> 'DeductionState':
        """Deduce flow facts"""
        state = DeductionState()
        match flow:
            case IPFlow():
                # update by source
                self.clues.update_state(flow.source[0], state)
                self.clues.update_state(flow.source[1], state)
                self.clues.update_state((flow.protocol, flow.source[2]), state)
                # update by target
                self.clues.update_state(flow.target[0], state)
                self.clues.update_state(flow.target[1], state)
                self.clues.update_state((flow.protocol, flow.target[2]), state)
        return state

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

    def update_state(self, reference: Any, state: 'DeductionState', weight: int = 0) -> None:
        """Update deduction state with clues for reference"""
        clues = self.clues.get(reference, [])
        for clue in clues:
            start_w = state.state.get(clue.item, 0)
            w = start_w + weight + clue.weight
            state.state[clue.item] = w
            self.update_state(clue.item, state, weight=w - start_w) # propagate weight increase

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

    def __repr__(self) -> str:
        r = []
        for item, weight in self.state.items():
            r.append(f"{item}: {weight}")
        return "\n".join(r)
