"""FIXME"""
# pylint: disable=pointless-statement
# pylint: disable=expression-not-assigned
# pylint: disable=cyclic-import

from typing import Self, Union
from urllib.request import urlretrieve
from diagrams import Diagram, Edge, Node
from diagrams.custom import Custom
from diagrams.aws.iot import IotSensor
from diagrams.ibm.user import Browser
from diagrams.generic import device, storage

from tdsaf.core.model import Host, HostType
import tdsaf.builder_backend as BB


class Visualizer2:
    """Security statement visualizer"""

    __font_size_node = "18"
    __font_size_edge = "16"
    __graph_attr = {"splines": "spline", "center": "true"}

    def __init__(self, system: 'BB.SystemBackend'):
        self.system = system
        self.show: bool=False
        self.delete: bool=False
        self.outformat: str="png"
        self.filename = system.system.long_name()
        self.should_create_diagram: bool=False
        self.nodes: dict={}
        self.connections: set[str]=set()
        self.images: dict[str, str]={}

    def add_images(self, d: dict['BB.HostBackend', str]) -> Self:
        """Use locally stored images for specified nodes in visualization.
            Must be .png images"""
        for host, file in d.items():
            self.images[host.entity.name] = file
        return self

    def add_remote_images(self, d: dict['BB.HostBackend', str]) -> Self:
        """Use images from the internet for specified nodes"""
        for host, url in d.items():
            name = host.entity.name
            urlretrieve(url, f"{name}.png")
            self.images[name] = f"{name}.png"
        return self

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

    def _get_node(self, host: Host) -> Union[Node, None]:
        """Returns a suitable visual representation for a given Host"""
        label = f"<<b>\n{self._sanitize_label(host.name)}</b>>"
        if (node := self._get_node_type(host)) is Custom:
            return node(label=label, icon_path=self.images[host.name], fontsize=self.__font_size_node)
        if node is not None:
            return node(label=label, fontsize=self.__font_size_node)
        return None

    def _add_connections(self, host: Host) -> None:
        """Adds connections between nodes"""
        for connection in host.connections:
            self.connections.add((
                connection.source.name, connection.target.parent.name, connection.target.name, "grey"
            ))

    def _add_ble_connection(self, host: Host) -> None:
        """Adds Bluetooth connections between devices"""
        if len(host.connections) < 2:
            return
        s = host.connections[0].source.name
        for connection in host.connections[1:]:
            self.connections.add((s, connection.source.name, "BLE", "blue"))

    def create_diagram(self) -> Self:
        """Create a diagram based on the security statement"""
        self.should_create_diagram = True
        return self

    def visualize(self) -> None:
        """Create the actual visualization and show it.
           Not to be used from a security statemnet."""
        if not self.should_create_diagram:
            return

        with Diagram(
            name="", filename=self.filename, graph_attr=self.__graph_attr,
            show=self.show, outformat=self.outformat
        ):
            for component in self.system.system.children:
                if 'Bluetooth' in component.description:
                    self._add_ble_connection(component)
                else:
                    self._add_connections(component)

                if (node:=self._get_node(component)) is not None:
                    self.nodes[component.name] = node

            for connection in self.connections:
                s, t, n, c = connection
                if s in self.nodes and t in self.nodes:
                    edge = Edge(label=f"<<b>{n}</b>>", minlen="4", style="dashed",
                                penwidth="3", fontsize=self.__font_size_edge, color=c)
                    self.nodes[s] >> edge >> self.nodes[t]
