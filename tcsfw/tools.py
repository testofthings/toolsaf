import json
import logging
import os.path
import pathlib
from datetime import datetime
from typing import Optional, List, Dict, Iterable, Tuple, Set, Self

from tcsfw.address import DNSName, IPAddress, AnyAddress, Addresses
from tcsfw.entity import ClaimAuthority, Entity
from tcsfw.event_interface import EventInterface
from tcsfw.model import NetworkNode, Addressable, IoTSystem, NodeComponent, Connection, Host
from tcsfw.property import PropertyKey
from tcsfw.traffic import EvidenceSource, Tool, Flow, IPFlow
from tcsfw.verdict import Verdict


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
        self.base_files: List[pathlib.Path] = []

    def run_tool(self, interface: EventInterface, source: EvidenceSource, arguments: str = None):
        """Perform the tool action"""
        pass

    def _add_base_files(self, arguments: Optional[str]):
        """Add base files from arguments"""
        if arguments:
            for fn in arguments.strip().split(":"):
                self.base_files.append(pathlib.Path(fn))

    def _get_file_by_name(self, name: str) -> Optional[pathlib.Path]:
        """Get data file by file name, if any"""
        for bf in self.base_files:
            if bf.is_dir():
                f = bf / name
                self.logger.debug("Check if %s", f.as_posix())
                if f.exists():
                    return f
            elif bf.name == name:
                return bf
        return None

    def coverage(self, data: Dict[Entity, Dict[PropertyKey, Set[Tool]]]):
        """Tell about covered entities and properties"""
        tool = self._coverage_tool()

        def do_coverage(e: Entity):
            cov = self._entity_coverage(e)
            for p in cov:
                data.setdefault(e, {}).setdefault(p, set()).add(tool)
            for c in e.get_children():
                do_coverage(c)
            if isinstance(e, Host):
                for c in e.connections:
                    do_coverage(c)
        do_coverage(self.system)

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        """Get node coverage data"""
        return []

    def _coverage_tool(self) -> Tool:
        """The tool to report in coverage"""
        return self.tool

class BaseFileCheckTool(CheckTool):
    """Check tool which scans set of files, no way to specify entries directly"""
    def __init__(self, tool_label: str, system: IoTSystem):
        super().__init__(tool_label, system)

    def run_tool(self, interface: EventInterface, source: EvidenceSource, arguments: str = None):
        source = source.rename(self.tool.name)
        self._add_base_files(arguments)
        me = self

        def read_file(data_file: pathlib.Path):
            if data_file.is_dir():
                if not me.data_file_suffix:
                    raise Exception(f"Can only specify data files here, problem with: {data_file.as_posix()}")
                for f in data_file.iterdir():
                    read_file(f)
            elif data_file.suffix == me.data_file_suffix:
                source.base_ref = data_file.absolute().as_posix()  # just override base reference
                source.timestamp = datetime.fromtimestamp(os.path.getmtime(data_file))
                me._check_file(data_file, interface, source)

        for f in self.base_files:
            if self.data_file_suffix and f.is_dir() and (f / self.tool_label).is_dir():
                # look inside 'tool/' directory
                f = f / self.tool_label  # look
            read_file(f)

    def _check_file(self, data_file: pathlib.Path, interface: EventInterface, source: EvidenceSource):
        raise NotImplementedError()


class EndpointCheckTool(CheckTool):
    """Check a service endpoint"""
    def __init__(self, tool_label: str, system: IoTSystem):
        super().__init__(tool_label, system)
        self.known_files: Dict[Addressable, pathlib.Path] = {}

    def run_tool(self, interface: EventInterface, source: EvidenceSource, arguments: str = None):
        source = source.rename(self.tool.name)
        self._add_base_files(arguments)
        for ent, path in self.known_files.items():
            add = Addresses.get_prioritized(ent.get_addresses())
            if not add:
                raise Exception(f"No known address for {ent} to scan {path.as_posix()}")
            source.timestamp = datetime.fromtimestamp(os.path.getmtime(path))
            source.base_ref = path.as_posix()
            self._check_entity(add, path, interface, source)

        for host in self.system.get_hosts(include_external=False):
            if host.status.verdict not in {Verdict.NOT_SEEN, Verdict.PASS}:
                continue
            if self._filter_node(host):
                # scan hosts
                self._scan_addresses(host, host.addresses, interface, source)
                continue
            for s in host.children:
                if s.status.verdict not in {Verdict.NOT_SEEN, Verdict.PASS}:
                    continue
                if self._filter_node(s):
                    self._scan_addresses(s, s.get_addresses(), interface, source)

    def _scan_addresses(self, entity: Addressable, addresses: Iterable[AnyAddress], interface: EventInterface,
                        source: EvidenceSource):
        """Scan addresses from a source"""
        self.logger.debug("Check for %s", entity)
        # First pass is DNS names, then IP addresses
        ads_sorted = [a for a in addresses if isinstance(a.get_host(), DNSName)]
        ads_sorted.extend([a for a in addresses if isinstance(a.get_host(), IPAddress)])
        for a in ads_sorted:
            a_file = self._get_file_by_endpoint(a)
            if a_file:
                self.logger.info("Scan %s", a_file.as_posix())
                source.timestamp = datetime.fromtimestamp(os.path.getmtime(a_file))
                source.base_ref = a_file.as_posix()
                self._check_entity(a, a_file, interface, source)

    def _get_file_by_endpoint(self, address: AnyAddress) -> Optional[pathlib.Path]:
        """Get data file by endpoint and tool label"""
        assert self.data_file_suffix, f"Data file suffix not set for {self}"
        host = address.get_host()
        pp = address.get_protocol_port()
        if pp is None:
            n = f"{self.tool_label}/{host}{self.data_file_suffix}"
        else:
            n = f"{self.tool_label}/{host}.{pp[0].value.lower()}.{pp[1]}{self.data_file_suffix}"
        return self._get_file_by_name(n)

    def _filter_node(self, node: NetworkNode) -> bool:
        """Filter checked entities"""
        return True

    def _check_entity(self,  endpoint: AnyAddress, data_file: pathlib.Path, interface: EventInterface, source: EvidenceSource):
        """Check entity with data"""
        raise NotImplementedError()


class NodeCheckTool(CheckTool):
    """Network node check tool"""
    def __init__(self, tool_label: str, system: IoTSystem):
        super().__init__(tool_label, system)
        self.known_files: Dict[NetworkNode, pathlib.Path] = {}

    def run_tool(self, interface: EventInterface, source: EvidenceSource, arguments: str = None):
        source = source.rename(self.tool.name)
        self._add_base_files(arguments)

        for ent, path in self.known_files.items():
            source.timestamp = datetime.fromtimestamp(os.path.getmtime(path))
            source.base_ref = path.as_posix()
            self._check_entity(ent, path, interface, source)
        tool = self

        def check_node(node: NetworkNode):
            if self._filter_component(node):
                a_file = self._get_file_by_name(node.name)
                if a_file:
                    source.timestamp = datetime.fromtimestamp(os.path.getmtime(a_file))
                    source.base_ref = a_file.as_posix()
                    tool._check_entity(node, a_file, interface, source)
            for c in node.children:
                check_node(c)
        if self.base_files:
            check_node(self.system)

    def _filter_component(self, node: NetworkNode) -> bool:
        """Filter checked entities"""
        return True

    def _check_entity(self, node: NetworkNode, data_file: pathlib.Path, interface: EventInterface,
                      source: EvidenceSource):
        """Check entity with data"""
        raise NotImplementedError()


class ComponentCheckTool(CheckTool):
    """Software check tool"""
    def __init__(self, tool_label: str, system: IoTSystem):
        super().__init__(tool_label, system)
        self.known_files: Dict[NodeComponent, pathlib.Path] = {}

    def run_tool(self, interface: EventInterface, source: EvidenceSource, arguments: str = None):
        source = source.rename(self.tool.name)
        self._add_base_files(arguments)

        for ent, path in self.known_files.items():
            source.timestamp = datetime.fromtimestamp(os.path.getmtime(path))
            source.base_ref = path.as_posix()
            self._check_entity(ent, path, interface, source)
        tool = self

        def check_component(node: NetworkNode):
            for c in node.components:
                if not tool._filter_component(c):
                    continue
                a_file = self._get_file_by_name(c.name)
                if a_file:
                    source.timestamp = datetime.fromtimestamp(os.path.getmtime(a_file))
                    source.base_ref = a_file.as_posix()
                    tool._check_entity(c, a_file, interface, source)
            for c in node.children:
                check_component(c)
        check_component(self.system)

    def _filter_component(self, component: NodeComponent) -> bool:
        """Filter checked entities"""
        return True

    def _check_entity(self, component: NodeComponent, data_file: pathlib.Path, interface: EventInterface,
                      source: EvidenceSource):
        """Check entity with data"""
        raise NotImplementedError()


class CustomFlowTool(CheckTool):
    """Send some custom flows"""
    def __init__(self, system: IoTSystem):
        super().__init__("", system)
        self.tool.name = "Test flows"
        self.flows: List[Flow] = []

    def parse_flows(self, flow_data: Iterable[str]) -> Self:
        for fd in flow_data:
            js = json.loads(fd)
            flow = IPFlow.parse_from_json(js)
            self.flows.append(flow)
            if js.get("reply"):
                self.flows.append(flow.reverse())
        return self

    def run_tool(self, interface: EventInterface, source: EvidenceSource, arguments: str = None):
        for f in self.flows:
            interface.connection(f)

