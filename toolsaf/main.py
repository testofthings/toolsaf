"""Model builder"""

from typing import Dict, List, Optional, Self, Tuple, Type, Union
from toolsaf.common.address import AnyAddress, HWAddress, HWAddresses, IPAddress, IPAddresses, Network
from toolsaf.common.basics import ConnectionType, HostType, ExternalActivity
from toolsaf.common.android import MobilePermissions


ProtocolType = Union['ProtocolConfigurer', Type['ProtocolConfigurer']]
ServiceOrGroup = Union['ServiceBuilder', 'ServiceGroupBuilder']

# pylint: disable=duplicate-code
# pylint: disable=cyclic-import

class ConfigurationException(Exception):
    """Feature or function misconfigured"""
    def __init__(self, message: str) -> None:
        super().__init__(message)


class SystemBuilder:
    """System model builder"""
    def network(self, subnet: str="") -> 'NetworkBuilder':
        """Configure network or subnetwork"""
        raise NotImplementedError()

    def device(self, name: str="") -> 'HostBuilder':
        """IoT device"""
        raise NotImplementedError()

    def backend(self, name: str="") -> 'HostBuilder':
        """Backend service"""
        raise NotImplementedError()

    def mobile(self, name: str="") -> 'HostBuilder':
        """Mobile device"""
        raise NotImplementedError()

    def browser(self, name: str="") -> 'HostBuilder':
        """Browser"""
        raise NotImplementedError()

    def any(self, name: str="", node_type: Optional[HostType] = None) -> 'HostBuilder':
        """Any host"""
        raise NotImplementedError()

    def infra(self, name: str="") -> 'HostBuilder':
        """Part of the testing infrastructure, not part of the system itself"""
        raise NotImplementedError()

    def multicast(self, address: str, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP multicast target"""
        raise NotImplementedError()

    def broadcast(self, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP broadcast target"""
        raise NotImplementedError()

    def data(self, names: List[str], personal: bool=False, password: bool=False) -> 'SensitiveDataBuilder':
        """Declare pieces of security-relevant data"""
        raise NotImplementedError()

    def online_resource(self, name: str, url: str, keywords: List[str]) -> Self:
        """Document online resource"""
        raise NotImplementedError()

    def attach_file(self, file_path: str, relative_to: Optional[str] = None) -> Self:
        """Attach a file to the model"""
        raise NotImplementedError()

    def diagram_visualizer(self) -> 'DiagramVisualizer':
        """Security statement visualization"""
        raise NotImplementedError()

    def load(self) -> 'EvidenceBuilder':
        """Load built-in evidence"""
        raise NotImplementedError()

    def ignore(self, file_type: str) -> 'IgnoreRulesBuilder':
        """Create a new ignore rule for given file type"""
        raise NotImplementedError()


class NodeBuilder:
    """Node builder base class"""
    def __init__(self, system: SystemBuilder) -> None:
        self.system = system

    def name(self, name: str) -> Self:
        """Define entity name, names with dot (.) are assumed to be DNS domain names"""
        raise NotImplementedError()

    def dns(self, name: str) -> Self:
        """Define DNS name"""
        raise NotImplementedError()

    def describe(self, text: str) -> Self:
        """Describe the system by a few sentences."""
        raise NotImplementedError()

    def external_activity(self, value: ExternalActivity) -> Self:
        """Define external activity"""
        raise NotImplementedError()

    def in_networks(self, *network: 'NetworkBuilder') -> Self:
        """Set networks this node interfaces with"""
        raise NotImplementedError()

    def software(self, name: Optional[str] = None) -> 'SoftwareBuilder':
        """Define software running here"""
        raise NotImplementedError()

    def visual(self) -> 'NodeVisualBuilder':
        """Create visual for the host"""
        raise NotImplementedError()

    def __rshift__(self, target: ServiceOrGroup) -> 'ConnectionBuilder':
        raise NotImplementedError()


class ServiceBuilder(NodeBuilder):
    """Service builder"""
    def type(self, value: ConnectionType) -> Self:
        """Configure connection type"""
        raise NotImplementedError()

    def authenticated(self, flag: bool) -> Self:
        """Is this service authenticated?"""
        raise NotImplementedError()

    def __truediv__(self, protocol: ProtocolType) -> 'ServiceGroupBuilder':
        """Pick or add the configured protocol to host"""
        raise NotImplementedError()


class ServiceGroupBuilder:
    """One or more services grouped"""
    def __truediv__(self, other: ServiceOrGroup | ProtocolType) -> Self:
        raise NotImplementedError()


class HostBuilder(NodeBuilder):
    """Host builder"""
    def __init__(self, system: SystemBuilder) -> None:
        NodeBuilder.__init__(self, system)

    def hw(self, address: str) -> Self:
        """Add HW address"""
        raise NotImplementedError()

    def ip(self, address: str) -> Self:
        """Add IP address"""
        raise NotImplementedError()

    def serve(self, *protocols: ProtocolType) -> Self:
        """Serve the configured protocol or protocols"""
        raise NotImplementedError()

    def __lshift__(self, multicast: ServiceBuilder) -> 'ConnectionBuilder':
        """Receive broadcast or multicast"""
        raise NotImplementedError()

    def cookies(self) -> 'CookieBuilder':
        """Configure cookies in a browser"""
        raise NotImplementedError()

    def use_data(self, *data: 'SensitiveDataBuilder') -> Self:
        """This host uses some sensitive data"""
        raise NotImplementedError()

    def os(self) -> 'OSBuilder':
        """Operating System definitions"""
        raise NotImplementedError()

    def __truediv__(self, protocol: ProtocolType) -> ServiceBuilder:
        """Pick or add the configured protocol"""
        raise NotImplementedError()

    def ignore_name_requests(self, *name: str) -> Self:
        """Ignore DNS name requests for these names"""
        raise NotImplementedError()

    def set_property(self, *key: str) -> Self:
        """Set a model properties"""
        raise NotImplementedError()

    def set_permissions(self, *permissions: MobilePermissions) -> Self:
        """Set permissions for a mobile application"""
        raise NotImplementedError()


class SensitiveDataBuilder:
    """Sensitive data builder"""
    def __init__(self, parent: SystemBuilder) -> None:
        self.parent = parent

    def used_by(self, hosts: List[HostBuilder]) -> Self:
        """This data used/stored in a host"""
        raise NotImplementedError()


class ConnectionBuilder:
    """Connection builder"""
    def logical_only(self) -> Self:
        """Only a logical link"""
        raise NotImplementedError()


class NetworkBuilder:
    """Network or subnet builder"""
    def __init__(self, network: Network) -> None:
        self.network = network

    def mask(self, mask: str) -> Self:
        """Set network mask(s)"""
        raise NotImplementedError()


class SoftwareBuilder:
    """Software builder"""
    def updates_from(self, source: Union[ConnectionBuilder, ServiceBuilder, HostBuilder]) -> Self:
        """Update mechanism"""
        raise NotImplementedError()

    def first_release(self, date: str) -> Self:
        """First release as YYYY-MM-DD"""
        raise NotImplementedError()

    def supported_until(self, date: str) -> Self:
        """Support end time YYYY-MM-DD"""
        raise NotImplementedError()

    def update_frequency(self, days: int) -> Self:
        """Target update frequency, days"""
        raise NotImplementedError()

    def sbom(self, components: Optional[List[str]]=None, file_path: str="") -> Self:
        """Add an SBOM from given list or SPDX JSON file.
           file_path is relative to the statement"""
        raise NotImplementedError()

class CookieBuilder:
    """Cookies in a browser"""
    def set(self, cookies: Dict[str, Tuple[str, str, str]]) -> Self:
        """Set cookies, name: domain, path, explanation"""
        raise NotImplementedError()


class NodeVisualBuilder:
    """Visual builder for a network node"""
    def hide(self) -> Self:
        """Hide this node from visualization"""
        raise NotImplementedError()

    def image(self, url: str, scale: int=100) -> Self:
        """Set URL to node image"""
        raise NotImplementedError()


class DiagramVisualizer:
    """Security statement visualizer"""
    def visualize(self) -> None:
        """Visualize statement"""
        raise NotImplementedError()

    def create_diagram(self) -> None:
        """Create a diagram based on the security statement"""
        raise NotImplementedError()


class IgnoreRulesBuilder:
    """Collection of ignore rules"""
    def properties(self, *results: Tuple[str, ...]) -> Self:
        """Set properties that this rule applies to. Leave empty for all properties"""
        raise NotImplementedError()

    def at(self, *locations: Union[SystemBuilder, NodeBuilder, ConnectionBuilder]) -> Self:
        """Set specific locations to which this rule is applied to"""
        raise NotImplementedError()

    def because(self, explanation: str) -> Self:
        """Set reason for the ignore"""
        raise NotImplementedError()


class ProtocolConfigurer:
    """Protocol configurer base class"""
    def __init__(self, name: str) -> None:
        self.name = name
        self.networks: List[NetworkBuilder] = []
        self.address: Optional[AnyAddress] = None

    def in_network(self, *network: NetworkBuilder) -> Self:
        """Specify networks for the service"""
        self.networks.extend(network)
        return self

    def at_address(self, address: str) -> Self:
        """Service in a specific address"""
        self.address = IPAddress.new(address)
        return self

    def __repr__(self) -> str:
        return self.name


class ARP(ProtocolConfigurer):
    """ARP configurer"""
    def __init__(self) -> None:
        ProtocolConfigurer.__init__(self, "ARP")


class DHCP(ProtocolConfigurer):
    """DHCP configurer"""
    def __init__(self, port: int=67) -> None:
        ProtocolConfigurer.__init__(self, "DHCP")
        self.port = port

    @classmethod
    def client(cls, port: int=68) -> 'UDP':
        """DHCP client port"""
        return UDP(port, name="DHCP client", administrative=True)


class DNS(ProtocolConfigurer):
    """DNS configurer"""
    def __init__(self, port: int=53, captive: bool=False) -> None:
        ProtocolConfigurer.__init__(self, "DNS")
        self.port = port
        self.captive = captive


class EAPOL(ProtocolConfigurer):
    """EAPOL configurer"""
    def __init__(self) -> None:
        ProtocolConfigurer.__init__(self, "EAPOL")


class FTP(ProtocolConfigurer):
    """FTP configurer"""
    def __init__(self, port: int=21) -> None:
        ProtocolConfigurer.__init__(self, "FTP")
        self.port = port


class HTTP(ProtocolConfigurer):
    """HTTP configurer"""
    def __init__(self, port: int=80, auth: Optional[bool] = None) -> None:
        ProtocolConfigurer.__init__(self, "HTTP")
        self.port = port
        self.auth = auth
        self.redirect_only = False

    def redirect(self) -> Self:
        """This is only HTTP redirect to TLS"""
        self.redirect_only = True
        return self


class ICMP(ProtocolConfigurer):
    """ICMP configurer"""
    def __init__(self) -> None:
        ProtocolConfigurer.__init__(self, "ICMP")


class IP(ProtocolConfigurer):
    """IPv4 or v6 configurer"""
    def __init__(self, name: str="IP", administration: bool=False) -> None:
        ProtocolConfigurer.__init__(self, name)
        self.administration = administration


class MQTT(ProtocolConfigurer):
    """MQTT Configurer"""
    def __init__(self, port: int=1883) -> None:
        ProtocolConfigurer.__init__(self, "MQTT")
        self.port = port


class TLS(ProtocolConfigurer):
    """TLS configurer"""
    def __init__(self, port: int=443, auth: Optional[bool] = None) -> None:
        ProtocolConfigurer.__init__(self, "TLS")
        self.port = port
        self.auth = auth


class NTP(ProtocolConfigurer):
    """NTP configurer"""
    def __init__(self, port: int=123) -> None:
        ProtocolConfigurer.__init__(self, "NTP")
        self.port = port


class SSH(ProtocolConfigurer):
    """SSH configurer"""
    def __init__(self, port: int=22) -> None:
        ProtocolConfigurer.__init__(self, "SSH")
        self.port = port


class TCP(ProtocolConfigurer):
    """TCP configurer"""
    def __init__(self, port: int, name: str="TCP", administrative: bool=False) -> None:
        ProtocolConfigurer.__init__(self, name)
        self.port = port
        self.name = name
        self.administrative = administrative


class UDP(ProtocolConfigurer):
    """UDP configurer"""
    def __init__(self, port: int, name: str="UDP", administrative: bool=False) -> None:
        ProtocolConfigurer.__init__(self, name)
        self.port = port
        self.name = name
        self.administrative = administrative


class BLEAdvertisement(ProtocolConfigurer):
    """BLE advertisement configurer"""
    def __init__(self, event_type: int) -> None:
        ProtocolConfigurer.__init__(self, "BLE Ad")
        self.event_type = event_type


class Proprietary(ProtocolConfigurer):
    """Configure proprietary protocol"""
    def __init__(self, protocol_name: str = "protocol", port: int = -1):
        ProtocolConfigurer.__init__(self, protocol_name)
        self.port = port


class OSBuilder:
    """Operating System builder"""
    def processes(self, owner_process: Dict[str, List[str]]) -> 'OSBuilder':
        """Define processes: mapping from owner to list of processes"""
        raise NotImplementedError()


class EvidenceBuilder:
    """Base class for data loaders"""
    def traffic(self, label: str) -> 'TrafficDataBuilder':
        """Fabricate evidence for testing or visualization"""
        raise NotImplementedError()


class TrafficDataBuilder:
    """Fabricate traffic data for testing or visualization"""
    def connection(self, flow: 'FlowBuilder') -> Self:
        """Add a connection"""
        raise NotImplementedError()

    def hw(self, entity: NodeBuilder, *hw_address: str) -> Self:
        """Set HW address(es) for a network node"""
        raise NotImplementedError()

    def ip(self, entity: NodeBuilder, *ip_address: str) -> Self:
        """Set IP address(es) for a network node"""
        raise NotImplementedError()

    def external_activity(self, entity: NodeBuilder, activity: ExternalActivity) -> Self:
        """Set external activity for a network node"""
        raise NotImplementedError()


class FlowBuilder:
    """Flow builder"""
    def __init__(self, protocol: str, source: Tuple[HWAddress, IPAddress, int]) -> None:
        self.protocol = protocol
        self.source = source
        self.target = HWAddresses.NULL, IPAddresses.NULL, 0

    def __rshift__(self, target: Tuple[str, str, int]) -> 'FlowBuilder':
        self.target = HWAddress.new(target[0]), IPAddress.new(target[1]), target[2]
        return self

    def __lshift__(self, source: Tuple[str, str, int]) -> 'FlowBuilder':
        self.target = self.source
        self.source = HWAddress.new(source[0]), IPAddress.new(source[1]), source[2]
        return self


class Builder:
    """Factory for creating builders"""
    @classmethod
    def new(cls, name: str="Unnamed system") -> SystemBuilder:
        """Create a new system builder"""
        # avoid circular import
        from toolsaf.builder_backend import SystemBackendRunner  # pylint: disable=import-outside-toplevel
        return SystemBackendRunner(name)

    @classmethod
    def UDP(cls, source_hw: str, source_ip: str, port: int) -> 'FlowBuilder':  # pylint: disable=invalid-name
        """Create a new UDP flow"""
        return FlowBuilder("UDP", (HWAddress.new(source_hw), IPAddress.new(source_ip), port))

    @classmethod
    def TCP(cls, source_hw: str, source_ip: str, port: int) -> 'FlowBuilder': # pylint: disable=invalid-name
        """Create a new TCP flow"""
        return FlowBuilder("TCP", (HWAddress.new(source_hw), IPAddress.new(source_ip), port))


if __name__ == "__main__":
    Builder.new().run()  # type: ignore [attr-defined]
