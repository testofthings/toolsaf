"""Entity selector and context"""

from typing import Iterator

from tdsaf.common.entity import Entity
from tdsaf.core.model import Host, Connection, Service


class EntitySelector:
    """Select entries by criteria"""
    def select(self, _entity: Entity, _context: 'SelectorContext') -> Iterator[Entity]:
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
