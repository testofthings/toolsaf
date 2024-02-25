import argparse
import io
import ipaddress
import itertools
import json
import logging
import pathlib
import sys

from typing import Any, Callable, Dict, List, Optional, Self, Tuple, Type, Union
from tcsfw.address import HWAddress, HWAddresses, IPAddress, IPAddresses
from tcsfw.selector import RequirementSelector
from tcsfw.basics import ConnectionType, HostType, Verdict, ExternalActivity


class SystemBuilder:
    """System model builder"""
    def network(self, mask: str) -> Self:
        raise NotImplementedError()

    def device(self, name="") -> 'HostBuilder':
        """IoT device"""
        raise NotImplementedError()

    def backend(self, name="") -> 'HostBuilder':
        """Backend service"""
        raise NotImplementedError()

    def mobile(self, name="") -> 'HostBuilder':
        """Mobile device"""
        raise NotImplementedError()

    def browser(self, name="") -> 'HostBuilder':
        """Browser"""
        raise NotImplementedError()

    def any(self, name="", node_type: HostType = None) -> 'HostBuilder':
        """Any host"""
        raise NotImplementedError()

    def infra(self, name="") -> 'HostBuilder':
        """Part of the testing infrastructure, not part of the system itself"""
        raise NotImplementedError()

    def multicast(self, address: str, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP multicast target"""
        raise NotImplementedError()

    def broadcast(self, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP broadcast target"""
        raise NotImplementedError()

    def data(self, names: List[str], personal=False, password=False) -> 'SensitiveDataBuilder':
        """Declare pieces of security-relevant data"""
        raise NotImplementedError()

    def online_resource(self, key: str, url: str) -> Self:
        """Document online resource"""
        raise NotImplementedError()

    def visualize(self) -> 'VisualizerBuilder':
        raise NotImplementedError()

    def load(self) -> 'EvidenceBuilder':
        raise NotImplementedError()

    def claims(self, base_label="explain") -> 'ClaimSetBuilder':
        raise NotImplementedError()


# Host types
BROWSER = HostType.BROWSER

# Connection types
ADMINISTRATIVE = ConnectionType.ADMINISTRATIVE
ENCRYPTED = ConnectionType.ENCRYPTED
PLAINTEXT = ConnectionType.UNKNOWN


# External activity
BANNED = ExternalActivity.BANNED
PASSIVE = ExternalActivity.PASSIVE
OPEN = ExternalActivity.OPEN
UNLIMITED = ExternalActivity.UNLIMITED


ProtocolType = Union['ProtocolConfigurer', Type['ProtocolConfigurer']]
ServiceOrGroup = Union['ServiceBuilder', 'ServiceGroupBuilder']


class NodeBuilder:
    def __init__(self, system: SystemBuilder):
        # NOTE: This is not called from subclasses, necessarily
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
        raise NotImplementedError()

    def software(self, name: Optional[str] = None) -> 'SoftwareBuilder':
        raise NotImplementedError()

    def visual(self) -> 'NodeVisualBuilder':
        """Create visual for the host"""
        raise NotImplementedError()

    def __rshift__(self, target: ServiceOrGroup) -> 'ConnectionBuilder':
        raise NotImplementedError()


class ServiceBuilder(NodeBuilder):
    """Service builder"""
    def __init__(self, system: SystemBuilder):
        super().__init__(system)

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
    def __init__(self, system: SystemBuilder):
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

    def __truediv__(self, protocol: ProtocolType) -> ServiceBuilder:
        """Pick or add the configured protocol"""
        raise NotImplementedError()

    def ignore_name_requests(self, *name: str) -> Self:
        """Ignore DNS name requests for these names"""
        raise NotImplementedError()

    def set_property(self, *key: str):
        """Set a model properties"""
        raise NotImplementedError()


class SensitiveDataBuilder:
    """Sensitive data builder"""
    def __init__(self, parent: SystemBuilder):
        self.parent = parent

    def used_by(self, *host: HostBuilder) -> Self:
        """This data used/stored in a host"""
        raise NotImplementedError()

    def authorize(self, *service: ServiceBuilder) -> Self:
        """This data is used for service authentication"""
        raise NotImplementedError()


class ConnectionBuilder:
    """Connection builder"""
    def logical_only(self) -> Self:
        """Only a logical link"""
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

    def update_frequency(self, days: float) -> Self:
        """Target update frequency, days"""
        raise NotImplementedError()


class CookieBuilder:
    """Cookies in a browser"""
    def set(self, cookies: Dict[str, Tuple[str, str, str]]):
        """Set cookies, name: domain, path, explanation"""
        raise NotImplementedError()


class NodeVisualBuilder:
    """Visual builder for a network node"""
    def hide(self) -> Self:
        raise NotImplementedError()

    def image(self, url: str, scale=100) -> Self:
        raise NotImplementedError()


class VisualizerBuilder:
    """Visual builder"""
    def place(self, *places: str) -> Self:
        """Place handles into image"""
        raise NotImplementedError()

    def where(self, handles: Dict[str, Union[NodeBuilder, NodeVisualBuilder]]) -> Self:
        """Name handles in the image"""
        raise NotImplementedError()


class ProtocolConfigurer:
    """Protocol configurer base class"""
    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return self.name


class ARP(ProtocolConfigurer):
    def __init__(self):
        ProtocolConfigurer.__init__(self, "ARP")


class DHCP(ProtocolConfigurer):
    def __init__(self, port=67):
        ProtocolConfigurer.__init__(self, "DHCP")
        self.port = port


class DNS(ProtocolConfigurer):
    def __init__(self, port=53, captive=False):
        ProtocolConfigurer.__init__(self, "DNS")
        self.port = port
        self.captive = captive

class EAPOL(ProtocolConfigurer):
    def __init__(self):
        ProtocolConfigurer.__init__(self, "EAPOL")


class HTTP(ProtocolConfigurer):
    def __init__(self, port=80, auth: Optional[bool] = None):
        ProtocolConfigurer.__init__(self, "HTTP")
        self.port = port
        self.auth = auth
        self.redirect_only = False

    def redirect(self) -> Self:
        """This is only HTTP redirect to TLS"""
        self.redirect_only = True
        return self


class ICMP(ProtocolConfigurer):
    def __init__(self):
        ProtocolConfigurer.__init__(self, "ICMP")


class IP(ProtocolConfigurer):
    def __init__(self, name="IP", administration=False):
        ProtocolConfigurer.__init__(self, name)
        self.administration = administration


class TLS(ProtocolConfigurer):
    def __init__(self, port=443, auth: Optional[bool] = None):
        ProtocolConfigurer.__init__(self, "TLS")
        self.port = port
        self.auth = auth


class NTP(ProtocolConfigurer):
    def __init__(self, port=123):
        ProtocolConfigurer.__init__(self, "NTP")
        self.port = port


class SSH(ProtocolConfigurer):
    def __init__(self, port=22):
        ProtocolConfigurer.__init__(self, "SSH")
        self.port = port


class TCP(ProtocolConfigurer):
    def __init__(self, port: int, name="TCP", administrative=False):
        ProtocolConfigurer.__init__(self, name)
        self.port = port
        self.name = name
        self.administrative = administrative


class UDP(ProtocolConfigurer):
    def __init__(self, port: int, name="UDP", administrative=False):
        ProtocolConfigurer.__init__(self, name)
        self.port = port
        self.name = name
        self.administrative = administrative


class BLEAdvertisement(ProtocolConfigurer):
    def __init__(self, event_type: int):
        ProtocolConfigurer.__init__(self, "BLE Ad")
        self.event_type = event_type


class ClaimBuilder:
    """Claim builder"""
    def key(self, *segments: str) -> Self:
        """Add property key"""
        raise NotImplementedError()

    def keys(self, *key: Tuple[str, ...]) -> Self:
        """Add property keys"""
        raise NotImplementedError()

    def verdict_ignore(self) -> Self:
        """Override verdict to ignore"""
        raise NotImplementedError()

    def verdict_pass(self) -> Self:
        """Override verdict to pass"""
        raise NotImplementedError()

    def at(self, *locations: Union[SystemBuilder, NodeBuilder, ConnectionBuilder]) -> 'Self':
        """Set claimed location(s)"""
        raise NotImplementedError()

    def software(self, *locations: NodeBuilder) -> 'Self':
        """Claims for software in the locations"""
        raise NotImplementedError()

    def vulnerabilities(self, *entry: Tuple[str, str]) -> Self:
        """Explain CVE-entries"""
        raise NotImplementedError()


class ClaimSetBuilder:
    """Builder for set of claims"""
    def set_base_label(self, base_label: str) -> Self:
        """Set label for the claims"""
        raise NotImplementedError()

    def claim(self, explanation: str, verdict=Verdict.PASS) -> ClaimBuilder:
        """Self-made claims"""
        raise NotImplementedError()

    def reviewed(self, explanation="", verdict=Verdict.PASS) -> ClaimBuilder:
        """Make reviewed claims"""
        raise NotImplementedError()

    def ignore(self, explanation="") -> ClaimBuilder:
        """Ignore claims or requirements"""
        raise NotImplementedError()

    def plan_tool(self, tool_name: str, group: Tuple[str, str], location: RequirementSelector,
                  *key: Tuple[str, ...]):
        """Plan use of a tool using the property keys it is supposed to set"""
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
    def __init__(self, protocol: str, source: Tuple[HWAddress, IPAddress, int]):
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
    def new(cls, name="Unnamed system") -> SystemBuilder:
        """Create a new system builder"""
        from tcsfw.builder_backend import SystemBackendRunner  # avoid circular import
        return SystemBackendRunner(name)

    @classmethod
    def UDP(cls, source_hw: str, source_ip: str, port: int) -> 'FlowBuilder':
        """Create a new UDP flow"""
        return FlowBuilder("UDP", (HWAddress.new(source_hw), IPAddress.new(source_ip), port))

    @classmethod
    def TCP(cls, source_hw: str, source_ip: str, port: int) -> 'FlowBuilder':
        """Create a new TCP flow"""
        return FlowBuilder("TCP", (HWAddress.new(source_hw), IPAddress.new(source_ip), port))


if __name__ == "__main__":
    Builder.new().run()
