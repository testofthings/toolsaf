"""FIXME"""
# pylint: disable=pointless-statement
# pylint: disable=expression-not-assigned
# pylint: disable=cyclic-import

from typing import Self
from urllib.request import urlretrieve
from diagrams import Diagram, Edge
from diagrams.custom import Custom
from diagrams.aws.iot import IotSensor
from diagrams.ibm.user import Browser
from diagrams.generic import device, storage

from tdsaf.core.model import Host, HostType
import tdsaf.builder_backend as BB

FONT_SIZE_NODE = "18"
FONT_SIZE_EDGE = "16"

class Visualizer2:
    """Security statement visualizer"""
    def __init__(self, system: 'BB.SystemBackend'):
        self.system = system
        self.nodes: dict={}
        self.connections: set[str]=set()
        self.images: dict[str, str]={}
        self.graph_attr = { # https://www.graphviz.org/doc/info/attrs.html
            "splines": "spline",
            "center": "true"
        }

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

    def _sanitize_labels(self, label: str) -> str:
        """Turn certain symbols to HTML character"""
        return label.replace("&", "&amp;")

    def _get_node(self, host: Host):
        """Returns a suitable visual representation for a given Host"""
        label = f"<<b>\n{self._sanitize_labels(host.name)}</b>>"
        if host.name in self.images:
            return Custom(label=label, icon_path=self.images[host.name], fontsize=FONT_SIZE_NODE)
        match host.host_type:
            case HostType.MOBILE:
                return device.Mobile(label=label, fontsize=FONT_SIZE_NODE)
            case HostType.DEVICE:
                return IotSensor(label=label, fontsize=FONT_SIZE_NODE)
            case HostType.BROWSER:
                return Browser(label=label, fontsize=FONT_SIZE_NODE)
            case HostType.REMOTE:
                return storage.Storage(label=label, fontsize=FONT_SIZE_NODE)

    def _add_connections(self, host: Host) -> None:
        """Adds connections between nodes"""
        for connection in host.connections:
            self.connections.add((
                host.name, connection.target.parent.name, connection.target.name, "grey"
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
        #system_name = self._sanitize_labels(self.system.system.long_name())
        system_name = self.system.system.long_name()
        with Diagram(name="", filename=system_name, graph_attr=self.graph_attr, show=True):
            for component in self.system.system.children:
                if 'Bluetooth' in component.description:
                    self._add_ble_connection(component)

                node = self._get_node(component)
                if node is None:
                    continue

                self.nodes[component.name] = node
                self._add_connections(component)

            for connection in self.connections:
                s, t, n, c = connection
                if s == t:
                    continue
                if s in self.nodes and t in self.nodes:
                    edge = Edge(label=f"<<b>{n}</b>>", minlen="4", style="dashed",
                                penwidth="3", fontsize=FONT_SIZE_EDGE, color=c)
                    self.nodes[s] >> edge >> self.nodes[t]

        return self
