"""Components for network nodes, hosts, services, etc."""

from dataclasses import dataclass
from typing import List, Optional, Dict, Set

from tcsfw.release_info import ReleaseInfo
from tcsfw.model import IoTSystem, NodeComponent, Connection, NetworkNode, Host, SensitiveData, Addressable


class Software(NodeComponent):
    """Software, firmware, etc. Each real host has one or more software components."""
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
    def ensure_default_software(cls, entity: Host):
        """Ensure host has at least the default software"""
        for s in entity.components:
            if isinstance(s, Software):
                return
        entity.add_component(Software(entity))

    @classmethod
    def list_software(cls, entity: NetworkNode) -> List['Software']:
        """List software components for an entity"""
        r = [c for c in entity.components if isinstance(c, Software)]
        return r

    @classmethod
    def get_software(cls, entity: NetworkNode, name="") -> Optional['Software']:
        """Find software, first or by name"""
        for s in entity.components:
            if not isinstance(s, Software):
                continue
            if not name or s.name == name:
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
        self.concept_name = "cookies"
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


class OperatingSystem(NodeComponent):
    """Operating system"""
    def __init__(self, entity: NetworkNode):
        super().__init__(entity, "OS")
        self.concept_name = "os"
        self.process_map: Dict[str, List[str]] = {}  # owner: process names

    @classmethod
    def get_os(cls, entity: NetworkNode, add=True) -> Optional['OperatingSystem']:
        """Get the OS for network node"""
        for c in entity.components:
            if isinstance(c, OperatingSystem):
                return c
        if not add:
            return None
        c = OperatingSystem(entity)
        entity.components.append(c)
        return c


class StoredData(NodeComponent):
    """Critical data stored in IoT system or network node"""
    def __init__(self, entity: NetworkNode):
        super().__init__(entity, "Stored critical data")
        self.concept_name = "stored-data"
        self.sub_components: List[DataReference] = []

    @classmethod
    def get_data(cls, entity: NetworkNode) -> 'StoredData':
        """Get data store, create if not present"""
        c = cls.find_data(entity)
        if c is None:
            c = StoredData(entity)
            entity.components.append(c)
        return c

    @classmethod
    def find_data(cls, entity: NetworkNode) -> Optional['StoredData']:
        """Find data store, if defined"""
        for c in entity.components:
            if isinstance(c, StoredData):
                return c
        return None


class DataReference(NodeComponent):
    """Critical data reference"""
    def __init__(self, entity: NetworkNode, data: SensitiveData):
        super().__init__(entity, data.name)
        self.concept_name = "data"
        self.data = data

    def long_name(self) -> str:
        return self.data.name + (f"@{self.entity.long_name()}" if not isinstance(self.entity, IoTSystem) else "")
