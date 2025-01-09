"""Traffic flow and events"""
# mypy: disable-error-code=arg-type

import datetime
from typing import Any, Callable, Tuple, Set, Optional, Self, Dict

from tdsaf.common.address import HWAddress, IPAddress, HWAddresses, IPAddresses, Network, Protocol, EndpointAddress, \
    AnyAddress, Addresses
from tdsaf.common.property import PropertyKey


class EvidenceSource:
    """Evidence source"""
    def __init__(self, name: str, base_ref: str="", label: str="") -> None:
        self.name = name
        self.target = ''
        self.base_ref = base_ref
        self.label = label or base_ref or self.name
        self.model_override = False  # model loading overrides values
        self.timestamp: Optional[datetime.datetime] = None

    def rename(self, name: Optional[str] = None, target: Optional[str] = None, base_ref: Optional[str] = None,
               label: Optional[str] = None) -> 'EvidenceSource':
        """Rename and create new source"""
        s = EvidenceSource(
            name if name is not None else self.name,
            self.base_ref if base_ref is None else base_ref,
            self.label if label is None else label)
        s.target = target if target is not None else self.target
        s.model_override = self.model_override
        return s

    def get_data_json(self, _id_resolver: Callable[[Any], Any]) -> Dict[None, None]:
        """Get extra data as JSON"""
        return {}

    def __repr__(self) -> str:
        return f"{self.name} {self.base_ref}"


class Evidence:
    """Piece of evidence"""
    def __init__(self, source: EvidenceSource, tail_ref: str="") -> None:
        self.source = source
        self.tail_ref = tail_ref

    def get_reference(self) -> str:
        """Get full reference. Returns an empty string if there is no info"""
        return self.source.base_ref + self.tail_ref

    def __repr__(self) -> str:
        return f"{self.source.name} {self.get_reference()}"


class Tool:
    """A tool for verification"""
    def __init__(self, name: str) -> None:
        self.name = name

    def __gt__(self, other: 'Tool') -> bool:
        return self.name.__gt__(other.name)

    def __eq__(self, other: object ) -> bool:
        return isinstance(other, Tool) and other.name == self.name

    def __hash__(self) -> int:
        return self.name.__hash__()

    def __repr__(self) -> str:
        return self.name


# No evidence
NO_EVIDENCE = Evidence(EvidenceSource("No evidence"))


class Event:
    """Event with evidence"""
    def __init__(self, evidence: Evidence) -> None:
        self.evidence = evidence

    def get_value_string(self) -> str:
        """Get value as string"""
        return ""

    def get_comment(self) -> str:
        """Get comment or empty"""
        return ""

    def get_info(self) -> str:
        """Short event information"""
        return self.get_value_string() or self.evidence.source.name

    def get_data_json(self, _id_resolver: Callable[[Any], Any]) -> Dict[None, None]:
        """Get JSON representation of data"""
        return {}

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict[str, Any],
                         entity_resolver: Callable[[Any], Any]) -> 'Event':
        """Placeholder for event decoding from JSON"""
        raise NotImplementedError()

    def __repr__(self) -> str:
        return self.get_value_string()

    def __hash__(self) -> int:
        return self.evidence.__hash__()

    def __eq__(self, v: object) -> bool:
        return self.evidence == v.evidence


class ServiceScan(Event):
    """Individual service scan result"""
    def __init__(self, evidence: Evidence, endpoint: AnyAddress, service_name: str="") -> None:
        super().__init__(evidence)
        self.endpoint = endpoint
        self.service_name = service_name

    def get_data_json(self, _id_resolver: Callable[[Any], Any]) -> Dict[str, str]:
        r = {
            "endpoint": self.endpoint.get_parseable_value(),
            "service": self.service_name,
        }
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict[str, Any],
                         _entity_resolver: Callable[[Any], Any]) -> 'ServiceScan':
        """Decode event from JSON"""
        endpoint = Addresses.parse_endpoint(data["endpoint"])
        name = data.get("service", "")
        return ServiceScan(evidence, endpoint, name)

    def __repr__(self) -> str:
        return f"{self.endpoint}"


class HostScan(Event):
    """Host scan result"""
    def __init__(self, evidence: Evidence, host: AnyAddress, endpoints: Set[EndpointAddress]) -> None:
        super().__init__(evidence)
        self.host = host
        self.endpoints = endpoints

    def get_data_json(self, _id_resolver: Callable[[Any], Any]) -> Dict[str, Any]:
        return {
            "host": self.host.get_parseable_value(),
            "endpoints": [e.get_parseable_value() for e in self.endpoints],
        }

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict[str, Any],
                         _entity_resolver: Callable[[Any], Any]) -> 'HostScan':
        """Decode event from JSON"""
        host = Addresses.parse_endpoint(data["host"])
        endpoints = {Addresses.parse_endpoint(e) for e in data.get("endpoints", [])}
        return HostScan(evidence, host, endpoints)


class Flow(Event):
    """Flow between two network points"""
    def __init__(self, evidence: Evidence, protocol: Protocol=Protocol.ANY) -> None:
        super().__init__(evidence)
        self.protocol = protocol
        self.network: Optional[Network] = None  # non-default network
        self.reply = False  # Is this reply? Set by inspector
        self.timestamp: Optional[datetime.datetime] = None
        self.properties: Dict[PropertyKey, Any] = {}  # optional properties for the connection

    def stack(self, target: bool) -> Tuple[AnyAddress]:
        """Get source or target address stack"""
        raise NotImplementedError()

    def port(self, _target: bool=True) -> int:
        """Get source or target (default) port or -1"""
        return -1

    def reverse(self) -> Self:
        """Reverse the flow"""
        raise NotImplementedError()

    def at_network(self, _network: Network) -> Self:
        """Change nework"""
        raise NotImplementedError()

    def set_evidence(self, evidence: Evidence) -> Self:
        """Set the evidence"""
        self.evidence = evidence
        return self

    def get_source_address(self) -> AnyAddress:
        """Get source top address"""
        return NotImplementedError() # type: ignore[return-value]

    def get_target_address(self) -> AnyAddress:
        """Get target top address"""
        return NotImplementedError() # type: ignore[return-value]

    def get_data_json(self, _id_resolver: Callable[[Any], Any]) -> Dict[str, Any]:
        r = {}  # protocol set by subclass, which knows the default
        if self.protocol != Protocol.ETHERNET:
            r["protocol"] = self.protocol.value
        if self.properties:
            p_r = r["properties"] = {}
            for k, v in self.properties.items():
                p_r[k.get_name()] = k.get_value_json(v, {})
        return r

    def decode_properties_json(self, data: Dict[str, Any]) -> None:
        """Decode properties from JSON"""
        for k, v in data.get("properties", {}).items():
            key = PropertyKey.parse(k)
            value = key.decode_value_json(v)
            self.properties[key] = value

    def __hash__(self) -> int:
        return self.protocol.__hash__() ^ hash(self.properties)

    def __eq__(self, v: object) -> bool:
        return self.protocol == v.protocol and self.properties == v.properties and self.network == v.network


class EthernetFlow(Flow):
    """Ethernet flow"""
    def __init__(self, evidence: Evidence, source: HWAddress, target: HWAddress, payload: int=-1,
                 protocol: Protocol=Protocol.ETHERNET) -> None:
        super().__init__(evidence, protocol)
        self.source = source
        self.target = target
        self.payload = payload

    def stack(self, target: bool) -> Tuple[AnyAddress]:
        return (self.target,) if target else (self.source,)

    def port(self, _target: bool=True) -> int:
        return self.payload  # both ways

    def get_source_address(self) -> AnyAddress:
        return self.source

    def get_target_address(self) -> AnyAddress:
        return self.target

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict[str, str]:
        r = super().get_data_json(id_resolver)
        if self.protocol != Protocol.ETHERNET:
            r["protocol"] = self.protocol.value
        r["source"] = f"{self.source}"
        r["target"] = f"{self.target}"
        if self.payload >= 0:
            r["payload"] = self.payload
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict[str, Any],
                         _entity_resolver: Callable[[Any], Any]) -> 'EthernetFlow':
        protocol = Protocol.get_protocol(data.get("protocol"), Protocol.ETHERNET)
        source = HWAddress.new(data["source"])
        target = HWAddress.new(data["target"])
        payload = data.get("payload", -1)
        r = EthernetFlow(evidence, source, target, payload, protocol)
        r.decode_properties_json(data)
        if data.get("reverse", False):
            r = r.reverse()
        return r

    @classmethod
    def new(cls, protocol: Protocol, address: str) -> 'EthernetFlow':
        """New ethernet-based protocol flow"""
        return EthernetFlow(NO_EVIDENCE, HWAddress.new(address), HWAddresses.NULL, protocol=protocol)

    def reverse(self) -> 'EthernetFlow':
        return EthernetFlow(self.evidence, self.target, self.source, self.payload, self.protocol)

    def at_network(self, network: Network) -> 'EthernetFlow':
        f = EthernetFlow(self.evidence, self.source, self.target, self.payload)
        f.network = network
        return f

    def __rshift__(self, target: str) -> 'EthernetFlow':
        self.target = HWAddress.new(target)
        return self

    def __lshift__(self, source: str) -> 'EthernetFlow':
        self.target = self.source
        self.source = HWAddress.new(source)
        return self

    def __repr__(self) -> str:
        s = self.source
        t = self.target
        pt = f" 0x{self.payload:04x}" if self.payload >= 0 else ""
        return f"{s} >> {t}{pt} {self.protocol.value.upper()}"

    def __hash__(self) -> int:
        return self.source.__hash__() ^ self.target.__hash__() ^ self.payload ^ self.protocol.__hash__() \
            ^ hash(self.network)

    def __eq__(self, other: object ) -> bool:
        if not isinstance(other, EthernetFlow):
            return False
        return self.source == other.source and self.payload == other.payload and self.target == other.target \
            and super().__eq__(other)


class IPFlow(Flow):
    """Flow between two IP network points"""
    def __init__(self, evidence: Evidence,
                 source: Tuple[HWAddress, IPAddress, int] = (HWAddresses.NULL, IPAddresses.NULL, 0),
                 target: Tuple[HWAddress, IPAddress, int] = (HWAddresses.NULL, IPAddresses.NULL, 0),
                 protocol: Protocol=Protocol.ANY) -> None:
        super().__init__(evidence, protocol)
        self.source = source
        self.target = target

    @classmethod
    def IP(cls, source_hw: str, source_ip: str, protocol: int) -> 'IPFlow': # pylint: disable=invalid-name
        """New IP flow"""
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), protocol),
                      protocol=Protocol.IP)

    @classmethod
    def UDP(cls, source_hw: str, source_ip: str, port: int) -> 'IPFlow':  # pylint: disable=invalid-name
        """New UDP flow"""
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), port),
                      protocol=Protocol.UDP)

    @classmethod
    def TCP(cls, source_hw: str, source_ip: str, port: int) -> 'IPFlow': # pylint: disable=invalid-name
        """New TCP flow"""
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), port),
                      protocol=Protocol.TCP)

    @classmethod
    def udp_flow(cls, source_hw: str=HWAddresses.NULL.data, source_ip: str="0.0.0.0", source_port: int=0,
                 target_hw: str=HWAddresses.NULL.data, target_ip: str="0.0.0.0", target_port: int=0) -> 'IPFlow':
        """New UDP flow with both endpoints"""
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), source_port),
                      target=(HWAddress.new(target_hw), IPAddress.new(target_ip), target_port), protocol=Protocol.UDP)

    @classmethod
    def tcp_flow(cls, source_hw: str=HWAddresses.NULL.data, source_ip: str="0.0.0.0", source_port: int=0,
                 target_hw: str=HWAddresses.NULL.data, target_ip: str="0.0.0.0", target_port: int=0) -> 'IPFlow':
        """New TCP flow with both endpoints"""
        return IPFlow(NO_EVIDENCE, source=(HWAddress.new(source_hw), IPAddress.new(source_ip), source_port),
                      target=(HWAddress.new(target_hw), IPAddress.new(target_ip), target_port), protocol=Protocol.TCP)

    def stack(self, target: bool) -> Tuple[AnyAddress, ...]:
        end = self.target if target else self.source
        return tuple(end[:2])

    def port(self, target: bool=True) -> int:
        return self.target[2] if target else self.source[2]

    def reverse(self) -> 'IPFlow':
        return IPFlow(self.evidence, self.target, self.source, self.protocol)

    def at_network(self, network: Network) -> 'IPFlow':
        f = IPFlow(self.evidence, self.source, self.target, self.protocol)
        f.network = network
        return f

    def new_evidence(self, evidence: Evidence) -> 'IPFlow':
        """New flow with new evidence"""
        flow = IPFlow(evidence, self.source, self.target, self.protocol)
        flow.evidence = evidence
        return flow

    def get_source_address(self) -> AnyAddress:
        return self.source[0] if self.source[1].is_null() else self.source[1]

    def get_target_address(self) -> AnyAddress:
        return self.target[0] if self.target[1].is_null() else self.target[1]

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict[str, Any]:
        r = super().get_data_json(id_resolver)
        r["protocol"] = self.protocol.value
        if not self.source[0].is_null():
            r["source_hw"] = f"{self.source[0]}"
        if not self.source[1].is_null():
            r["source"] = f"{self.source[1]}"
        if self.source[2] >= 0:
            r["source_port"] = self.source[2]
        if not self.target[0].is_null():
            r["target_hw"] = f"{self.target[0]}"
        if not self.target[1].is_null():
            r["target"] = f"{self.target[1]}"
        if self.target[2] >= 0:
            r["target_port"] = self.target[2]
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict[str, Any],
                         entity_resolver: Callable[[Any], Any]) -> 'IPFlow':
        protocol = Protocol.get_protocol(data["protocol"])
        s_hw = HWAddress.new(data.get("source_hw")) if "source_hw" in data else HWAddresses.NULL
        s_ip = IPAddress.new(data.get("source")) if "source" in data else IPAddresses.NULL
        s_port = data.get("source_port", -1)
        t_hw = HWAddress.new(data.get("target_hw")) if "target_hw" in data else HWAddresses.NULL
        t_ip = IPAddress.new(data.get("target")) if "target" in data else IPAddresses.NULL
        t_port = data.get("target_port", -1)
        r = IPFlow(evidence, source=(s_hw, s_ip, s_port), target=(t_hw, t_ip, t_port), protocol=protocol)
        r.decode_properties_json(data)
        if data.get("reverse", False):
            r = r.reverse()
        return r

    def __rshift__(self, target: Tuple[str, str, int]) -> 'IPFlow':
        self.target = HWAddress.new(target[0]), IPAddress.new(target[1]), target[2]
        return self

    def __lshift__(self, source: Tuple[str, str, int]) -> 'IPFlow':
        self.target = self.source
        self.source = HWAddress.new(source[0]), IPAddress.new(source[1]), source[2]
        return self

    def __repr__(self) -> str:
        s = self.source
        t = self.target
        return f"{s[0]} {s[1]}:{s[2]} >> {t[0]} {t[1]}:{t[2]} {self.protocol.value.upper()}"

    def __hash__(self) -> int:
        return self.source.__hash__() ^ self.target.__hash__() ^ self.protocol.__hash__() ^ hash(self.network)

    def __eq__(self, other: object ) -> bool:
        if not isinstance(other, IPFlow):
            return False
        return self.source == other.source and self.target == other.target and super().__eq__(other)

    @classmethod
    def parse_from_json(cls, value: Dict[str, Any]) -> 'IPFlow':
        """Parse event from a string"""
        # Form 1
        protocol_str = "udp" if "udp" in value else "tcp" if "tcp" in value else None
        if protocol_str:
            p_value = value[protocol_str]
            s_hw, s_ip, s_port = p_value["source"]
            t_hw, t_ip, t_port = p_value["target"]
            return IPFlow(NO_EVIDENCE, (HWAddress.new(s_hw), IPAddress.new(s_ip), s_port),
                      (HWAddress.new(t_hw), IPAddress.new(t_ip), t_port), protocol=Protocol.get_protocol(protocol_str))
        # Form 2
        protocol = Protocol.get_protocol(value["protocol"])
        s_ip, s_port = IPAddress.parse_with_port(value["source"])
        t_ip, t_port = IPAddress.parse_with_port(value["target"])
        s_hw = HWAddress.new(value["source_hw"]) if "source_hw" in value else HWAddress.from_ip(s_ip)
        t_hw = HWAddress.new(value["target_hw"]) if "target_hw" in value else HWAddress.from_ip(t_ip)
        return IPFlow(NO_EVIDENCE, (s_hw, s_ip, s_port), (t_hw, t_ip, t_port), protocol=protocol)


class BLEAdvertisementFlow(Flow):
    """Bluetooth Low-Energy Advertisement flow"""
    def __init__(self, evidence: Evidence, source: HWAddress, event_type: int) -> None:
        super().__init__(evidence, Protocol.BLE)
        self.source = source
        self.event_type = event_type

    def stack(self, target: bool) -> Tuple[AnyAddress]:
        return (Addresses.BLE_Ad,) if target else (self.source,)

    def port(self, target: bool=True) -> int:
        return self.event_type if target else -1

    def reverse(self) -> Self:
        return self

    def at_network(self, network: Network) -> 'BLEAdvertisementFlow':
        f = BLEAdvertisementFlow(self.evidence, self.source, self.event_type)
        f.network = network
        return f

    def get_source_address(self) -> AnyAddress:
        return (Addresses.BLE_Ad if self.reply else self.source)

    def get_target_address(self) -> AnyAddress:
        return (self.source if self.reply else Addresses.BLE_Ad)

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict[str, Any]:
        r = super().get_data_json(id_resolver)
        r["source"] = f"{self.source}"
        r["event_type"] = self.event_type
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict[str, Any],
                         entity_resolver: Callable[[Any], Any]) -> 'BLEAdvertisementFlow':
        source = HWAddress.new(data["source"])
        event_type = data["event_type"]
        r = BLEAdvertisementFlow(evidence, source, event_type)
        r.decode_properties_json(data)
        if data.get("reverse", False):
            r = r.reverse()
        return r

    def __repr__(self) -> str:
        return f"{self.source} >> 0x{self.event_type:02x} {self.protocol.value.upper()}"

    def __hash__(self) -> int:
        return self.source.__hash__() ^ self.event_type ^ self.protocol.__hash__() ^ hash(self.network)

    def __eq__(self, other: object ) -> bool:
        if not isinstance(other, BLEAdvertisementFlow):
            return False
        return self.source == other.source and self.event_type == other.event_type and super().__eq__(other)
