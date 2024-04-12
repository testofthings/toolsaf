"""Base classes for tool integration"""

from io import BytesIO
import json
import logging
from typing import Optional, Dict

from tcsfw.address import DNSName, IPAddress, AnyAddress
from tcsfw.entity import ClaimAuthority
from tcsfw.event_interface import EventInterface
from tcsfw.model import NetworkNode, Addressable, IoTSystem, NodeComponent
from tcsfw.traffic import Evidence, EvidenceSource, Tool, IPFlow
from tcsfw.basics import Status


class CheckTool:
    """A security check tool"""
    def __init__(self, tool_label: str, system: IoTSystem):
        self.tool_label = tool_label
        self.tool = Tool(tool_label)  # human readable
        self.data_file_suffix = ""
        self.system = system
        self.authority = ClaimAuthority.TOOL
        self.logger = logging.getLogger(tool_label)
        self.send_events = True  # True to send events to interface
        self.load_baseline = False  # True to load baseline, false to check it

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        """Process a tool result file or stream"""
        # Read a data file
        raise NotImplementedError(f"In {self.__class__.__name__}")

    def get_file_by_name(self, name: str) -> str:
        """Get data file by name"""
        assert self.data_file_suffix, "Data file suffix not set"
        return f"{name}{self.data_file_suffix}"

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


class BaseFileCheckTool(CheckTool):
    """Check tool which scans set of files, no way to specify entries directly"""

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        raise NotImplementedError()


class EndpointCheckTool(CheckTool):
    """Check a service endpoint"""
    def __init__(self, tool_label: str, data_file_suffix: str, system: IoTSystem):
        super().__init__(tool_label, system)
        # map from file names into addressable entities
        self.data_file_suffix = data_file_suffix
        self.file_name_map: Dict[str, Addressable] = {}
        self.create_file_name_map()

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource):
        key = self.file_name_map.get(file_name)
        if key:
            self.logger.info("processing (%s) %s", source.label, file_name)
            self.process_stream(key, data, interface, source)
            return True
        return False

    def create_file_name_map(self):
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

    def map_addressable(self, entity: Addressable):
        """Map addressable entity to file names"""
        # First pass is DNS names, then IP addresses
        addresses = entity.get_addresses()
        ads_sorted = [a for a in addresses if isinstance(a.get_host(), DNSName)]
        ads_sorted.extend([a for a in addresses if isinstance(a.get_host(), IPAddress)])
        for a in ads_sorted:
            a_file_name = self.get_file_by_endpoint(a)
            if a_file_name not in self.file_name_map:
                self.file_name_map[a_file_name] = a

    def filter_node(self, _node: NetworkNode) -> bool:
        """Filter checked entities"""
        return True

    def process_stream(self,  endpoint: AnyAddress, stream: BytesIO, interface: EventInterface, source: EvidenceSource):
        """Process file from stream"""
        raise NotImplementedError()


class NodeCheckTool(CheckTool):
    """Network node check tool"""
    def __init__(self, tool_label: str, data_file_suffix: str, system: IoTSystem):
        super().__init__(tool_label, system)
        self.data_file_suffix = data_file_suffix
        self.file_name_map: Dict[str, NetworkNode] = {}
        self.create_file_name_map()

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource):
        key = self.file_name_map.get(file_name)
        if key:
            self.logger.info("processing (%s) %s", source.label, file_name)
            self.process_stream(key, data, interface, source)
            return True
        return False

    def create_file_name_map(self):
        """Create file name map"""
        tool = self

        def check_component(node: NetworkNode):
            for c in node.children:
                if not tool.filter_component(c):
                    continue
                self.file_name_map[tool.get_file_by_name(c.name)] = c
                check_component(c)
        check_component(self.system)


    def process_stream(self, node: NetworkNode, data_file: BytesIO, interface: EventInterface, source: EvidenceSource):
        """Check entity with data"""
        raise NotImplementedError()

    def filter_component(self, _node: NetworkNode) -> bool:
        """Filter checked entities"""
        return True


class ComponentCheckTool(CheckTool):
    """Software check tool"""
    def __init__(self, tool_label: str, data_file_suffix: str, system: IoTSystem):
        super().__init__(tool_label, system)
        self.data_file_suffix = data_file_suffix
        self.file_name_map: Dict[str, NodeComponent] = {}
        self._create_file_name_map()

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource):
        key = self.file_name_map.get(file_name)
        if key:
            self.logger.info("processing (%s) %s", source.label, file_name)
            self.process_stream(key, data, interface, source)
            return True
        return False

    def _create_file_name_map(self):
        """Create file name map"""
        tool = self

        def check_component(node: NetworkNode):
            for c in node.components:
                if not tool.filter_component(c):
                    continue
                self.file_name_map[tool.get_file_by_name(c.name)] = c
            for c in node.children:
                check_component(c)
        check_component(self.system)

    def filter_component(self, _component: NodeComponent) -> bool:
        """Filter checked entities"""
        return True

    def process_stream(self, component: NodeComponent, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource):
        """Check entity with data"""
        raise NotImplementedError()


class SimpleFlowTool(BaseFileCheckTool):
    """Simple flow tool powered by list of flows"""
    def __init__(self, system: IoTSystem):
        super().__init__("flow", system)
        self.tool.name = "JSON flow reader"

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        raw_json = json.load(data)
        for raw_flow in raw_json.get("flows", []):
            flow = IPFlow.parse_from_json(raw_flow)
            flow.evidence = Evidence(source)
            interface.connection(flow)
