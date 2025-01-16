"""Security Statement Visualizer"""
# pylint: disable=pointless-statement
# pylint: disable=expression-not-assigned
# pylint: disable=cyclic-import

from typing import Self, Union, Dict, List, Tuple, Any
from urllib.request import urlretrieve
from diagrams import Diagram, Edge, Node
from diagrams.custom import Custom
from diagrams.aws.iot import IotSensor
from diagrams.ibm.user import Browser
from diagrams.generic import device, storage

from toolsaf.common.verdict import Verdict
from toolsaf.common.basics import HostType
from toolsaf.core.model import Host
import toolsaf.builder_backend as BB
from toolsaf.main import DiagramVisualizer as DV


class DiagramVisualizer(DV):
    """Security statement visualizer"""

    __font_size_node = "18"
    __font_size_edge = "16"
    __graph_attr = {"splines": "spline", "center": "true"}

    def __init__(self, system: 'BB.SystemBackend'):
        self.system = system
        self.show: bool = False
        self.delete: bool = False
        self.outformat: str = "png"
        self.filename = system.system.long_name()
        self.should_create_diagram: bool = False
        self.nodes: Dict[str, Node] = {}
        self.connections: set[Tuple[str, Any, str, str, str]] = set()
        self.images: Dict[str, str] = {}

    def set_outformat(self, create_diagram: Union[str, None], show_diagram: Union[str, None]) -> None:
        """Set outputformat for created diagram"""
        if create_diagram is not None and show_diagram is not None:
            self.outformat = next((format for format in [create_diagram, show_diagram] if format != "png"), "png")
        else:
            self.outformat = str(show_diagram or create_diagram)

    def set_file_name(self, file_name: str = "") -> None:
        """Set filename for created diagram. Default is the system's name"""
        if file_name:
            self.filename = file_name

    def add_images(self, host_image_dict: Dict['BB.HostBackend', str]) -> Self:
        """Use locally stored images for specified nodes in visualization.
            Must be .png images"""
        for host_backend, file_path in host_image_dict.items():
            self.images[host_backend.entity.name] = file_path
        return self

    def add_remote_images(self, host_image_url_dict: Dict['BB.HostBackend', str]) -> Self:
        """Use images from the internet for specified nodes"""
        for host_backend, url in host_image_url_dict.items():
            name = host_backend.entity.name
            urlretrieve(url, f"{name}.png")
            self.images[name] = f"{name}.png"
        return self

    def _get_hosts(self) -> List[Host]:
        return [
            host for host in self.system.system.get_hosts() if host.is_relevant()
        ]

    def _sanitize_label(self, label: str) -> str:
        """Turn certain symbols to HTML character"""
        return label.replace("&", "&amp;")

    def _custom_image(self, label: str) -> Custom:
        return Custom(
            label=label,
            icon_path="",
            fontsize=self.__font_size_node
        )

    def _get_node_type(self, host: Host) -> Union[Node, None]:
        """Returns a suitable node type for a given Host."""
        if host.name in self.images:
            return Custom
        match host.host_type:
            case HostType.DEVICE:
                return IotSensor
            case HostType.MOBILE:
                return device.Mobile
            case HostType.BROWSER:
                return Browser
            case HostType.REMOTE:
                return storage.Storage
            case _:
                return None

    def _get_verdict_text(self, verdict: Verdict) -> str:
        if verdict in [Verdict.PASS, Verdict.FAIL]:
            return f"[{verdict.value}] "
        return " "

    def _get_label_color(self, verdict: Verdict) -> str:
        if verdict == Verdict.PASS:
            return "darkgreen"
        if verdict == Verdict.FAIL:
            return "darkred"
        return "black"

    def _get_node_label(self, host: Host, verdict: Verdict) -> str:
        if (verdict_text := self._get_verdict_text(verdict)) != " ":
            return f"<<font color='{self._get_label_color(verdict)}'><b>" + \
                   f"\n\n<br/>{verdict_text}<br/>"                          + \
                   f"{self._sanitize_label(host.name)}</b></font>>"

        return f"<<font color='{self._get_label_color(verdict)}'><b>" + \
               f"\n{self._sanitize_label(host.name)}</b></font>>"

    def _get_node(self, host: Host) -> Union[Node, None]:
        """Returns a suitable visual representation for a given Host"""
        verdict = host.get_verdict({})
        label = self._get_node_label(host, verdict)
        if (node := self._get_node_type(host)) is Custom:
            return node(label=label, icon_path=self.images[host.name], fontsize=self.__font_size_node)
        if node is not None:
            return node(label=label, fontsize=self.__font_size_node)
        return None

    def _add_connections(self, host: Host) -> None:
        """Adds connections between nodes"""
        for connection in host.connections:
            if connection.target.parent is None:
                continue
            verdict = connection.get_verdict({})
            self.connections.add((
                connection.source.name, connection.target.parent.name,
                f"{self._get_verdict_text(verdict)}{connection.target.name}", "black", self._get_label_color(verdict)
            ))

    def _add_ble_connection(self, host: Host) -> None:
        """Adds Bluetooth connections between devices"""
        if len(host.connections) < 2:
            return
        source_name = host.connections[0].source.name
        for connection in host.connections[1:]:
            verdict = connection.get_verdict({})
            self.connections.add((
                source_name, connection.source.name, f"{self._get_verdict_text(verdict)}BLE",
                "blue", self._get_label_color(verdict)
            ))

    def create_diagram(self) -> None:
        """Execute diagram visualization and handle any exceptions"""
        try:
            self.visualize()
        except Exception as e:
            if 'ExecutableNotFound' in str(type(e)):
                raise OSError("Missing Graphviz? You can install it here: https://graphviz.org/download/") from e
            raise e

    def visualize(self) -> None:
        """Create the actual visualization and show it"""
        with Diagram(
            name="", filename=self.filename, graph_attr=self.__graph_attr,
            show=self.show, outformat=self.outformat
        ):
            for host in self._get_hosts():
                if 'Bluetooth' in host.description:
                    self._add_ble_connection(host)
                else:
                    self._add_connections(host)

                if (node := self._get_node(host)) is not None:
                    self.nodes[host.name] = node

            for connection in self.connections:
                source, target, connection_name, edge_color, label_color = connection
                if source in self.nodes and target in self.nodes:
                    edge = Edge(
                        label=f"<<font color='{label_color}'><b>{connection_name}</b></font>>",
                        minlen="4", style="dashed", penwidth="3", fontsize=self.__font_size_edge, color=edge_color
                    )
                    self.nodes[source] >> edge >> self.nodes[target]
