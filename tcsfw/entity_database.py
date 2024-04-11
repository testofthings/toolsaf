"""Base class and default database implementation"""

import logging
from typing import Any, Iterable, Optional, Dict, List
from tcsfw.event_interface import EventInterface
from tcsfw.traffic import Event


class EntityDatabase:
    """Store and retrieve events, later entities, etc."""
    def __init__(self):
        self.logger = logging.getLogger("database")
        self.events_thru_db = False  # all events through DB?
        # local ID integers for entities and connections, usable for persistent DB
        self.ids: Dict[Any, int] = {}
        self.reverse_id: List[Any] = []

    def restore_stored(self, _interface: EventInterface) -> Iterable[Event]:
        """Restore stored events after model is loaded"""
        return []

    def reset(self, source_filter: Dict[str, bool] = None):
        """Reset database cursor"""

    def next_pending(self) -> Optional[Event]:
        """Fetch next pending event, if any"""
        return None

    def get_id(self, entity) -> int:
        """Get ID for an entity or whatever, int"""
        raise NotImplementedError()

    def get_entity(self, id_value: int) -> Optional[Any]:
        """Get entity by id, if any"""
        raise NotImplementedError()

    def put_event(self, event: Event):
        """Store an event"""
        raise NotImplementedError()


class InMemoryDatabase(EntityDatabase):
    """Store and retrieve events, later entities, etc."""
    def __init__(self):
        EntityDatabase.__init__(self)
        self.trail: List[Event] = []
        self.trail_filter: Dict[str, bool] = {}  # key is label, not present == False
        self.cursor = 0

    def reset(self, source_filter: Dict[str, bool] = None):
        self.cursor = 0
        self.trail_filter = source_filter or {}

    def next_pending(self) -> Optional[Event]:
        while self.cursor < len(self.trail):
            e = self.trail[self.cursor]
            self.cursor += 1
            source = e.evidence.source
            if self.trail_filter.get(source.label, False):
                self.logger.debug("process #%d %s", self.cursor, e)
                return e
            else:
                self.logger.debug("filtered #%d %s", self.cursor, e)
        return None

    def get_id(self, entity) -> int:
        i = self.ids.get(entity, -1)
        if i == -1:
            self.ids[entity] = i = len(self.ids)
            self.reverse_id.append(entity)
        return i

    def get_entity(self, id_value: int) -> Optional[Any]:
        return self.reverse_id[id_value] if id_value < len(self.reverse_id) else None

    def put_event(self, event: Event):
        if not self.events_thru_db and self.cursor == len(self.trail):
            self.cursor += 1  # assuming event is sent directly
        self.trail.append(event)
        source = event.evidence.source
        self.trail_filter.setdefault(source.label, True)
