from typing import Tuple, List, Dict, Set, Callable, Iterator, Optional, Iterable, Any

from tcsfw.claim import Claim
from tcsfw.entity import Entity
from tcsfw.model import Host, Connection, Service, HostType, ConnectionType, IoTSystem
from tcsfw.property import PropertyKey


class EntitySelector:
    """Select entries by criteria"""
    def select(self, entity: Entity, context: 'SelectorContext') -> Iterator[Entity]:
        """Select starting from entity and in a context"""
        return iter(())

    def get_name(self) -> str:
        """Get selector name"""
        return "selector"


class SelectorContext:
    """Selector context"""
    def include_host(self, entity: Host) -> bool:
        """Is the given host included?"""
        return entity.is_relevant()

    def include_service(self, entity: Service) -> bool:
        """Is the given host included?"""
        return entity.is_relevant()

    def include_connection(self, entity: Connection) -> bool:
        """Is the given host included?"""
        return entity.is_relevant()


class Requirement:
    """A requirement"""
    def __init__(self, identifier: Tuple[str, str], text: str, selector: EntitySelector, claim: Claim):
        self.identifier = identifier
        self.text = text
        self.selector = selector
        self.claim = claim
        self.priority = 0
        self.properties: Dict[PropertyKey, Any] = {}
        self.section_name = ""
        self.target_name = ""

    def identifier_string(self, tail_only=False) -> str:
        if tail_only:
            return self.identifier[1]
        return f"{self.identifier[0]} {self.identifier[1]}"

    def get_text(self, with_identifier=False) -> str:
        if not with_identifier:
            return self.text
        return f"{self.identifier_string(tail_only=True)}: {self.text}"

    def __repr__(self):
        return f"{self.identifier_string()}: {self.text}"


class SpecificationSelectorContext(SelectorContext):
    """Specify entities for specification"""
    def include_host(self, entity: Host) -> bool:
        return entity.is_original() and entity.host_type != HostType.ADMINISTRATIVE

    def include_service(self, entity: Service) -> bool:
        return entity.is_original() and entity.host_type != HostType.ADMINISTRATIVE

    def include_connection(self, entity: Connection) -> bool:
        return entity.is_original() and entity.con_type not in {ConnectionType.ADMINISTRATIVE, ConnectionType.LOGICAL}


class Specification:
    """Specification, collection of requirements"""
    def __init__(self, specification_id: str, specification_name: str, ignored=None):
        # FIXME: Nuked ignored parameter
        self.specification_id = specification_id
        self.specification_name = specification_name
        self.all_ids: Set[str] = {specification_id}
        self.requirement_map: Dict[str, Requirement] = {}
        self.cutoff_priority = 0  # by default, do not show values smaller than this
        self.short_infos = False
        self.default_sections = True
        self.custom_sections: List[str] = []

    def list_requirements(self, cutoff: Optional[int] = None) -> Iterable[Requirement]:
        """List requirements, priority at least the cutoff"""
        co = self.cutoff_priority if cutoff is None else cutoff
        return [r for r in self.requirement_map.values() if r.priority >= co]

    def get_entity_selector(self, system: IoTSystem) -> SelectorContext:
        """Get selector context which filters the scope of the specification"""
        return SpecificationSelectorContext()

    def get_sorting_key(self) -> Callable[[Requirement], int]:
        """Get a sorting key - function for requirements of this specification"""
        key = {r: i for i, r in enumerate(self.requirement_map.values())}
        return lambda r: key.get(r, -1)

    def _req(self, req_id: str, requirement: Requirement) -> Requirement:
        """Add new requirement"""
        requirement.identifier = self.specification_id, req_id
        self.requirement_map[req_id] = requirement
        return requirement

    def get_short_info(self, requirement: Requirement) -> str:
        """Get possible short information texts for requirements"""
        if not self.short_infos:
            return ""
        info = requirement.claim.description
        if "." in info:
            info = info[:info.index(".")]
        return info

    def create_aliases(self, selected: Iterable[Tuple[Requirement, Entity, Claim]]) \
            -> Dict[Tuple[Requirement, Entity, Claim], str]:
        """Create aliases for entities selected in different requirements"""
        return {}

    def __getitem__(self, identifier: str) -> Requirement:
        return self.requirement_map[identifier]

    def __repr__(self) -> str:
        s = [f"{r}" for r in self.requirement_map.values()]
        return "\n".join(s)
