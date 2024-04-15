"""Components for network nodes, hosts, services, etc."""

from dataclasses import dataclass
from typing import List, Optional, Dict, Set

from tcsfw.release_info import ReleaseInfo
from tcsfw.model import NodeComponent, Connection, NetworkNode, Host, SensitiveData, Addressable


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


@dataclass(frozen=True)
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
        """Get cookies for an entity, create if needed"""
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


class DataStorages(NodeComponent):
    """Data storages in IoT system or network node"""
    def __init__(self, entity: NetworkNode, name="Sensitive data", data: List[SensitiveData] = None):
        super().__init__(entity, name)
        self.concept_name = "data"
        self.sub_components: List[DataReference] = [DataReference(self, d) for d in (data or [])]

    @classmethod
    def get_storages(cls, entity: NetworkNode, add=False) -> 'DataStorages':
        """Get data storages for an entity, created and even added if needed"""
        for c in entity.components:
            if isinstance(c, DataStorages):
                return c
        c = DataStorages(entity)
        if add:
            entity.components.append(c)
        return c


class DataReference(NodeComponent):
    """Sensitive data reference"""
    def __init__(self, usage: DataStorages, data: SensitiveData):
        super().__init__(usage.entity, data.name)
        self.concept_name = "data"
        self.data = data
