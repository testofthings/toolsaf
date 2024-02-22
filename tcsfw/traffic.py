import datetime
from typing import Tuple, Set, Optional, Self, Union, Dict

from tcsfw.address import HWAddress, IPAddress, HWAddresses, IPAddresses, Protocol, EndpointAddress, AnyAddress, \
    Addresses


class EvidenceSource:
    """Evidence source"""
    def __init__(self, name: str, base_ref="", label=""):
        self.name = name
        self.base_ref = base_ref
        self.label = label or base_ref or self.name
        self.timestamp: Optional[datetime.datetime] = None

    def rename(self, name: str) -> Self:
        """Rename and create new source"""
        return EvidenceSource(name, self.base_ref, self.label)

    def __repr__(self):
        return f"{self.name} {self.base_ref}"


class Evidence:
    """Piece of evidence"""
    def __init__(self, source: EvidenceSource, tail_ref=""):
        self.source = source
        # self.timestamp # FIXME
        self.tail_ref = tail_ref

    def get_reference(self) -> str:
        """Get full reference"""
        return self.source.base_ref + self.tail_ref

    def __repr__(self):
        return f"{self.source.name} {self.get_reference()}"


class Tool:
    """A tool for verification"""
    def __init__(self, name: str):
        self.name = name

    def __gt__(self, other: 'Tool'):
        return self.name.__gt__(other.name)

    def __eq__(self, other):
        return isinstance(other, Tool) and other.name == self.name

    def __hash__(self):
        return self.name.__hash__()

    def __repr__(self):
        return self.name


"""No evidence"""
NO_EVIDENCE = Evidence(EvidenceSource("No evidence"))


class Event:
    """Event with evidence"""
    def __init__(self, evidence: Evidence):
        self.evidence = evidence
        self.update_entity_status = True  # update entity etc. status?

    def get_value_string(self) -> str:
        """Get value as string"""
        return ""

    def get_comment(self) -> str:
        """Get comment or empty"""
        return ""

    def get_info(self) -> str:
        """Short event information"""
        return self.get_value_string() or self.evidence.source.name

    def __repr__(self):
        return self.get_value_string()


class ServiceScan(Event):
    """Individual service scan result"""
    def __init__(self, evidence: Evidence, endpoint: EndpointAddress, service_name=""):
        super().__init__(evidence)
        self.endpoint = endpoint
        self.service_name = service_name

    def __repr__(self):
        return f"{self.endpoint}"


class HostScan(Event):
    def __init__(self, evidence: Evidence, host: AnyAddress, endpoints: Set[EndpointAddress]):
        super().__init__(evidence)
        self.host = host
        self.endpoints = endpoints


class Flow(Event):
    """Flow between two network points"""
    def __init__(self, evidence: Evidence, protocol=Protocol.ANY):
        super().__init__(evidence)
        self.protocol = protocol
        self.reply = False  # Is this reply? Set by inspector
        self.timestamp: Optional[datetime.datetime] = None

    def stack(self, target: bool) -> Tuple[AnyAddress]:
        """Get source or target address stack"""
        raise NotImplementedError()

    def port(self, target=True) -> int:
        """Get source or target (default) port or -1"""
        return -1

    def reverse(self) -> Self:
        """Reverse the flow"""
        raise NotImplementedError()

    def set_evidence(self, evidence: Evidence) -> Self:
        """Set the evidence"""
        self.evidence = evidence
        return self

    def get_source_address(self) -> AnyAddress:
        """Get source top address"""
        return NotImplementedError()

    def get_target_address(self) -> AnyAddress:
        """Get target top address"""
        return NotImplementedError()


class EthernetFlow(Flow):
    def __init__(self, evidence: Evidence, source: HWAddress, target: HWAddress, payload=-1,
                 protocol=Protocol.ETHERNET):
        super().__init__(evidence, protocol)
        self.source = source
        self.target = target
        self.payload = payload

    def stack(self, target: bool) -> Tuple[AnyAddress]:
        return (self.target,) if target else (self.source,)

    def port(self, target=True) -> int:
        return self.payload  # both ways

    def get_source_address(self) -> AnyAddress:
        return self.source

    def get_target_address(self) -> AnyAddress:
        return self.target

    @classmethod
    def new(cls, protocol: Protocol, address: str) -> 'EthernetFlow':
        """New ethernet-based protocol flow"""
        return EthernetFlow(NO_EVIDENCE, HWAddress.new(address), HWAddresses.NULL, protocol=protocol)

    def reverse(self) -> Self:
        """Reverse the flow"""
        return EthernetFlow(self.evidence, self.target, self.source, self.payload, self.protocol)

    def __rshift__(self, target: str) -> 'EthernetFlow':
        self.target = HWAddress.new(target)
        return self

    def __lshift__(self, source: str) -> 'EthernetFlow':
        self.target = self.source
        self.source = HWAddress.new(source)
        return self

    def __repr__(self):
        s = self.source
        t = self.target
        pt = f" 0x{self.payload:04x}" if self.payload >= 0 else ""
        return f"{s} >> {t}{pt} {self.protocol.value.upper()}"

    def __hash__(self):
        return self.source.__hash__() ^ self.target.__hash__() ^ self.payload ^ self.protocol.__hash__()

    def __eq__(self, other):
        if not isinstance(other, EthernetFlow):
            return False
        return self.protocol == other.protocol and self.source == other.source and self.payload == other.payload \
            and self.target == other.target


class IPFlow(Flow):
    """Flow between two IP network points"""
    def __init__(self, evidence: Evidence,
                 source: Tuple[HWAddress, IPAddress, int] = (HWAddresses.NULL, IPAddresses.NULL, 0),
                 target: Tuple[HWAddress, IPAddress, int] = (HWAddresses.NULL, IPAddresses.NULL, 0),
                 protocol=Protocol.ANY):
        super().__init__(evidence, protocol)
        self.source = source
        self.target = target

    @classmethod
    def IP(cls, source_hw: str, source_ip: str, protocol: int) -> 'IPFlow':
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), protocol), 
                      protocol=Protocol.IP)

    @classmethod
    def UDP(cls, source_hw: str, source_ip: str, port: int) -> 'IPFlow':
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), port), 
                      protocol=Protocol.UDP)

    @classmethod
    def TCP(cls, source_hw: str, source_ip: str, port: int) -> 'IPFlow':
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), port), 
                      protocol=Protocol.TCP)

    @classmethod
    def udp_flow(cls, source_hw=HWAddresses.NULL.data, source_ip="0.0.0.0", source_port=0,
                 target_hw=HWAddresses.NULL.data, target_ip="0.0.0.0", target_port=0):
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), source_port),
                      target=(HWAddress.new(target_hw), IPAddress.new(target_ip), target_port), protocol=Protocol.UDP)

    @classmethod
    def tcp_flow(cls, source_hw=HWAddresses.NULL.data, source_ip="0.0.0.0", source_port=0,
                 target_hw=HWAddresses.NULL.data, target_ip="0.0.0.0", target_port=0):
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), source_port),
                      target=(HWAddress.new(target_hw), IPAddress.new(target_ip), target_port), protocol=Protocol.TCP)

    def stack(self, target: bool) -> Tuple[AnyAddress]:
        end = self.target if target else self.source
        return tuple(end[:2])

    def port(self, target=True) -> int:
        return self.target[2] if target else self.source[2]

    def reverse(self) -> Self:
        return IPFlow(self.evidence, self.target, self.source, self.protocol)

    def get_source_address(self) -> AnyAddress:
        return self.source[0] if self.source[1].is_null() else self.source[1]

    def get_target_address(self) -> AnyAddress:
        return self.target[0] if self.target[1].is_null() else self.target[1]

    def __rshift__(self, target: Tuple[str, str, int]) -> 'IPFlow':
        self.target = HWAddress.new(target[0]), IPAddress.new(target[1]), target[2]
        return self

    def __lshift__(self, source: Tuple[str, str, int]) -> 'IPFlow':
        self.target = self.source
        self.source = HWAddress.new(source[0]), IPAddress.new(source[1]), source[2]
        return self

    def __repr__(self):
        s = self.source
        t = self.target
        return f"{s[0]} {s[1]}:{s[2]} >> {t[0]} {t[1]}:{t[2]} {self.protocol.value.upper()}"

    def __hash__(self):
        return self.source.__hash__() ^ self.target.__hash__() ^ self.protocol.__hash__()

    def __eq__(self, other):
        if not isinstance(other, IPFlow):
            return False
        return self.protocol == other.protocol and self.source == other.source and self.target == other.target

    @classmethod
    def parse_from_json(cls, value: Dict) -> 'IPFlow':
        """Parse event from a string"""
        # Form 1
        protocol = "udp" if "udp" in value else "tcp" if "tcp" in value else None
        if protocol:
            p_value = value[protocol]
            s_hw, s_ip, s_port = p_value["source"]
            t_hw, t_ip, t_port = p_value["target"]
            return IPFlow(NO_EVIDENCE, (HWAddress.new(s_hw), IPAddress.new(s_ip), s_port),
                          (HWAddress.new(t_hw), IPAddress.new(t_ip), t_port), protocol=Protocol.get_protocol(protocol))
        # Form 2
        protocol = Protocol.get_protocol(value["protocol"])
        s_ip, s_port = IPAddress.parse_with_port(value["source"])
        t_ip, t_port = IPAddress.parse_with_port(value["target"])
        s_hw = HWAddress.new(value["source_hw"]) if "source_hw" in value else HWAddress.from_ip(s_ip)
        t_hw = HWAddress.new(value["target_hw"]) if "target_hw" in value else HWAddress.from_ip(t_ip)
        return IPFlow(NO_EVIDENCE, (s_hw, s_ip, s_port), (t_hw, t_ip, t_port), protocol=protocol)


class BLEAdvertisementFlow(Flow):
    """Bluetooth Low-Energy Advertisement flow"""
    def __init__(self, evidence: Evidence, source: HWAddress, event_type: int):
        super().__init__(evidence, Protocol.BLE)
        self.source = source
        self.event_type = event_type

    def stack(self, target: bool) -> Tuple[AnyAddress]:
        return (Addresses.BLE_Ad,) if target else (self.source,)

    def port(self, target=True) -> int:
        return self.event_type if target else -1

    def reverse(self) -> Self:
        """Reverse the flow"""
        return self

    def get_source_address(self) -> AnyAddress:
        return (Addresses.BLE_Ad if self.reply else self.source)

    def get_target_address(self) -> AnyAddress:
        return (self.source if self.reply else Addresses.BLE_Ad)

    def __repr__(self):
        return f"{self.source} >> 0x{self.event_type:02x} {self.protocol.value.upper()}"

    def __hash__(self):
        return self.source.__hash__() ^ self.event_type ^ self.protocol.__hash__()

    def __eq__(self, other):
        if not isinstance(other, BLEAdvertisementFlow):
            return False
        return self.protocol == other.protocol and self.source == other.source and self.event_type == other.event_type
