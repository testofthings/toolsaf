"""Base classes for tool integration"""

from io import BufferedReader
import json
import logging
from functools import wraps
from typing import Optional, Dict, Set, Callable, Any, Generic, TypeVar

from toolsaf.common.address import Addresses, DNSName, EntityTag, IPAddress, AnyAddress
from toolsaf.core.event_interface import EventInterface
from toolsaf.core.model import NetworkNode, Addressable, IoTSystem, NodeComponent
from toolsaf.common.traffic import Evidence, EvidenceSource, Tool, IPFlow
from toolsaf.common.basics import Status
from toolsaf.main import ConfigurationException


class IncorrectBatchFileExcpetion(Exception):
    """ToolAdapter failed to parse a file"""
    def __init__(self, message: str) -> None:
        super().__init__(message)


def handle_incorrect_batch_file(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator for handling IncorrectBatchFileExcpetion raised by ToolAdapters"""
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except IncorrectBatchFileExcpetion as e:
            args[0].logger.warning("Failed to parse file %s. %s", args[2], str(e))
            return None
    return wrapper


class ToolAdapter:
    """Security tool adapter base class"""
    def __init__(self, tool_label: str, system: IoTSystem) -> None:
        self.tool_label = tool_label
        self.tool = Tool(tool_label)  # human readable
        self.data_file_suffix = ""
        self.system = system
        self.logger = logging.getLogger(tool_label)
        self.send_events = True  # True to send events to interface
        self.load_baseline = False  # True to load baseline, false to check it

    def process_file(self, data: BufferedReader, file_name: str,
                     interface: EventInterface, source: EvidenceSource) -> bool:
        """Process a tool result file or stream"""
        # Read a data file
        raise NotImplementedError(f"In {self.__class__.__name__}")

    def get_file_by_endpoint(self, address: AnyAddress) -> Optional[str]:
        """Get data file by endpoint address"""
        assert self.data_file_suffix, f"Data file suffix not set for {self}"
        host = address.get_host()
        pp = address.get_protocol_port()
        if pp is None:
            n = f"{host}{self.data_file_suffix}"
        else:
            n = f"{host}.{pp[0].value.lower()}.{pp[1]}{self.data_file_suffix}"
        return n

    def get_processed_files(self) -> Set[str]:
        """Get processed files to check if there are other files"""
        return set()

class SystemWideTool(ToolAdapter):
    """Apply tool output to system as output indicates"""

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        raise NotImplementedError()


class EndpointTool(ToolAdapter):
    """Tool applies to endpoints"""
    def __init__(self, tool_label: str, data_file_suffix: str, system: IoTSystem) -> None:
        super().__init__(tool_label, system)
        # map from file names into addressable entities
        self.data_file_suffix = data_file_suffix
        self.file_name_map: Dict[str, AnyAddress] = {}
        self.create_file_name_map()

    def filter_node(self, _node: NetworkNode) -> bool:
        """Filter checked endpoints by the corresponding node"""
        return True

    def process_endpoint(self, endpoint: AnyAddress, stream: BufferedReader, interface: EventInterface,
                         source: EvidenceSource) -> None:
        """Process result file for specific endpoint"""
        raise NotImplementedError()

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        key = self.file_name_map.get(file_name)
        if key:
            self.logger.info("processing (%s) %s", source.label, file_name)
            source.target = str(key)
            self.process_endpoint(key, data, interface, source)
            return True
        return False

    def create_file_name_map(self) -> None:
        """Create file name map"""
        for host in self.system.get_hosts(include_external=False):
            if host.status != Status.EXPECTED:
                continue
            if self.filter_node(host):
                # scan hosts
                self.map_addressable(host)
                continue
            for s in host.children:
                if s.status != Status.EXPECTED:
                    continue
                if self.filter_node(s):
                    self.map_addressable(s)

    def map_addressable(self, entity: Addressable) -> None:
        """Map addressable entity to file names"""
        # First pass is Tags, DNS names, then IP addresses
        addresses = entity.get_addresses()
        ads_sorted = [a for a in addresses if a.is_tag()]
        ads_sorted.extend([a for a in addresses if isinstance(a.get_host(), DNSName)])
        ads_sorted.extend([a for a in addresses if isinstance(a.get_host(), IPAddress)])
        for a in ads_sorted:
            a_file_name = self.get_file_by_endpoint(a)
            if a_file_name not in self.file_name_map and isinstance(a_file_name, str):
                self.file_name_map[a_file_name] = a

    def get_processed_files(self) -> Set[str]:
        return set(self.file_name_map.keys())


E = TypeVar("E", NetworkNode, NodeComponent)


class EntityFileMap(Generic[E]):
    """Map data file names to entities by entity name or by entity tag.
    The tag does not change when entity is renamed, so the data files named by the tag still match.
    E.g. 'Device 1.json' and 'Device_1.json' match 'Device 1' with tag Device_1."""
    def __init__(self, data_file_suffix: str) -> None:
        self.data_file_suffix = data_file_suffix
        self.by_name: Dict[str, E] = {}
        self.by_tag: Dict[str, Optional[E]] = {}  # None for tags of many entities
        self.files: Dict[E, str] = {}  # files mapped so far

    def add(self, entity: E, name: str, tag: Optional[EntityTag]) -> None:
        """Add entity with name and tag, if any"""
        self.by_name[f"{name}{self.data_file_suffix}"] = entity
        if tag:
            tag_file = f"{tag.tag}{self.data_file_suffix}"
            self.by_tag[tag_file] = entity if self.by_tag.get(tag_file, entity) is entity else None

    def map_file(self, file_name: str) -> Optional[E]:
        """Map file name to entity, check that one entity does not have many files"""
        entity = self.by_name.get(file_name)
        if entity is None:
            if file_name not in self.by_tag:
                return None
            entity = self.by_tag[file_name]
            if entity is None:
                raise ConfigurationException(f"Data file {file_name} matches many entities by tag")
        if (other := self.files.setdefault(entity, file_name)) != file_name:
            raise ConfigurationException(f"Data files {other} and {file_name} are both for {entity.long_name()}")
        return entity

    def get_file_names(self) -> Set[str]:
        """Get file names by entity names"""
        return set(self.by_name.keys())


class NetworkNodeTool(ToolAdapter):
    """Tool applies to network nodes"""
    def __init__(self, tool_label: str, data_file_suffix: str, system: IoTSystem) -> None:
        super().__init__(tool_label, system)
        self.data_file_suffix = data_file_suffix
        self.file_name_map: EntityFileMap[NetworkNode] = EntityFileMap(data_file_suffix)
        self.create_file_name_map()

    def filter_node(self, _node: NetworkNode) -> bool:
        """Filter checked nodes"""
        return True

    def process_node(self, node: NetworkNode, data_file: BufferedReader, interface: EventInterface,
                     source: EvidenceSource) -> None:
        """Process file for specific network node"""
        raise NotImplementedError()

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        key = self.file_name_map.map_file(file_name)
        if key:
            self.logger.info("processing (%s) %s", source.label, file_name)
            self.process_node(key, data, interface, source)
            return True
        return False

    def create_file_name_map(self) -> None:
        """Create file name map"""
        tool = self

        def check_component(node: NetworkNode) -> None:
            for c in node.children:
                if not tool.filter_node(c):
                    continue
                self.file_name_map.add(c, c.name, Addresses.get_tag(c.addresses))
                check_component(c)
        check_component(self.system)

    def get_processed_files(self) -> Set[str]:
        return self.file_name_map.get_file_names()


class NodeComponentTool(ToolAdapter):
    """Tool applies to node components"""
    def __init__(self, tool_label: str, data_file_suffix: str, system: IoTSystem) -> None:
        super().__init__(tool_label, system)
        self.data_file_suffix = data_file_suffix
        self.file_name_map: EntityFileMap[NodeComponent] = EntityFileMap(data_file_suffix)
        self._create_file_name_map()

    def filter_component(self, _component: NodeComponent) -> bool:
        """Filter checked components"""
        return True

    def process_component(self, component: NodeComponent, data_file: BufferedReader, interface: EventInterface,
                          source: EvidenceSource) -> None:
        """Process file for specific component"""
        raise NotImplementedError()

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        key = self.file_name_map.map_file(file_name)
        if key:
            self.logger.info("processing (%s) %s", source.label, file_name)
            source.target = key.long_name()
            self.process_component(key, data, interface, source)
            return True
        return False

    def _create_file_name_map(self) -> None:
        """Create file name map"""
        tool = self

        def check_component(node: NetworkNode) -> None:
            for c in node.components:
                if not tool.filter_component(c):
                    continue
                self.file_name_map.add(c, c.name, c.tag)
            for n in node.children:
                check_component(n)
        check_component(self.system)

    def get_processed_files(self) -> Set[str]:
        return self.file_name_map.get_file_names()


class SimpleFlowTool(SystemWideTool):
    """Simple flow tool powered by list of flows"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("flow", system)
        self.tool.name = "JSON flow reader"

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        raw_json = json.load(data)
        for raw_flow in raw_json.get("flows", []):
            flow = IPFlow.parse_from_json(raw_flow)
            flow.evidence = Evidence(source)
            interface.connection(flow)
        return True
