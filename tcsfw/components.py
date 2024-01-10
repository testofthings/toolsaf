from dataclasses import dataclass
from dataclasses import dataclass
from typing import List, Optional, Dict, Set

from tcsfw.events import ReleaseInfo
from tcsfw.model import NodeComponent, Connection, NetworkNode, Host, PieceOfData, Service, Addressable


class Software(NodeComponent):
    """Software, firmware, etc."""
    def __init__(self, entity: NetworkNode, name: str = None):
        super().__init__(entity, self.default_name(entity) if name is None else name)
        self.concept_name = "software"
        self.info = ReleaseInfo(self.name)
        self.components: Dict[str, SoftwareComponent] = {}
        self.permissions: Set[str] = set()
        self.update_connections: List[Connection] = []

    @classmethod
    def default_name(cls, entity: NetworkNode) -> str:
        """Default SW name"""
        return f"{entity.long_name()} SW"

    def __repr__(self):
        return f"{self.name}\n{self.info_string()}"

    def reset(self):
        super().reset()
        self.info = ReleaseInfo(self.name)

    def info_string(self) -> str:
        s = []
        i = self.info
        if i.latest_release:
            s.append(f"Latest release {ReleaseInfo.print_time(i.latest_release)} {i.latest_release_name}")
        if i.first_release:
            s.append(f"First release {ReleaseInfo.print_time(i.first_release)}")
        if i.interval_days:
            s.append(f"Mean update interval {i.interval_days} days")
        return "\n".join(s)

    def get_host(self) -> Host:
        """Software always has host"""
        host = self.entity
        assert isinstance(host, Addressable)
        return host.get_parent_host()

    @classmethod
    def list_software(cls, entity: NetworkNode) -> List['Software']:
        """List software components, non-recursively. Create to host, if none found"""
        r = []
        for s in entity.components:
            if not isinstance(s, Software):
                continue
            r.append(s)
        if not r:
            assert isinstance(entity, Host), "Can only add software for hosts"
            r = [entity.add_component(Software(entity))]
        return r

    @classmethod
    def get_software(cls, entity: NetworkNode, name: str) -> Optional['Software']:
        """Find software by name"""
        for s in entity.components:
            if not isinstance(s, Software):
                continue
            if s.name == name:
                return s
        for c in entity.children:
            s = cls.get_software(c, name)
            if s:
                return s
        return None


@dataclass
class CookieData:
    """Cookie data"""
    domain: str = "/"
    path: str = "/"
    explanation: str = ""


class Cookies(NodeComponent):
    """Browser cookies"""
    def __init__(self, entity: NetworkNode, name="Cookies"):
        super().__init__(entity, name)
        self.cookies: Dict[str, CookieData] = {}

    @classmethod
    def cookies_for(cls, entity: NetworkNode) -> 'Cookies':
        for c in entity.components:
            if isinstance(c, Cookies):
                return c
        c = Cookies(entity)
        entity.add_component(c)
        return c


@dataclass
class SoftwareComponent:
    """Software component"""
    name: str
    version: str = ""


class DataUsage(NodeComponent):
    """Data usage"""
    def __init__(self, entity: NetworkNode, name="Critical data", data: List[PieceOfData] = None):
        super().__init__(entity, name)
        self.concept_name = "data"
        self.sub_components: List[DataReference] = [DataReference(self, d) for d in (data or [])]

    @classmethod
    def get_data_usage(cls, entity: NetworkNode) -> 'DataUsage':
        """Get data usage for an entity, created if needed"""
        for c in entity.components:
            if isinstance(c, DataUsage):
                return c
        c = DataUsage(entity)
        entity.components.append(c)
        return c

    @classmethod
    def map_authenticators(cls, system: NetworkNode, mapping: Dict[Service, List[PieceOfData]])\
            -> Dict[Service, List[PieceOfData]]:
        """Map authentication data from services using them"""
        for c in system.iterate(relevant_only=True):
            if isinstance(c, DataReference):
                for s in c.data.authenticator_for:
                    mapping.setdefault(s, []).append(c.data)
        return mapping


class DataReference(NodeComponent):
    def __init__(self, usage: DataUsage, data: PieceOfData):
        super().__init__(usage.entity, f"{data.name} @ {usage.entity.name}")
        self.concept_name = "data"
        self.data = data
