"""Addresses and protocols"""

import enum
import ipaddress
from ipaddress import IPv4Address, IPv6Address
from typing import Union, Optional, Tuple, Iterable, Self


class Protocol(enum.Enum):
    """Protocol identifiers"""
    ANY = ""

    ARP = "arp"
    DNS = "dns"
    ETHERNET = "eth"
    HTTP = "http"
    ICMP = "icmp"
    TCP = "tcp"
    IP = "ip"  # IPv4 or IPv6
    SSH = "ssh"
    TLS = "tls"  # or SSL
    UDP = "udp"

    BLE = "ble"

    @classmethod
    def get_protocol(cls, value: str, default: Optional['Protocol'] = None) -> Optional['Protocol']:
        """Get protocol by name"""
        try:
            return cls[value.upper()] if value else default
        except KeyError:
            return default


class AnyAddress:
    """Any address"""
    def get_ip_address(self) -> Optional['IPAddress']:
        """Get possible IP address here"""
        return None

    def get_hw_address(self) -> Optional['HWAddress']:
        """Get possible hardware address here"""
        return None

    def get_host(self) -> Optional['AnyAddress']:
        """Get host or self"""
        return self

    def get_origin(self) -> 'AnyAddress':
        """Get the origin, loosely after URL naming, which is host and possible port"""
        return self

    def get_protocol_port(self) -> Optional[Tuple[Protocol, int]]:
        """Get protocol and port, if any"""
        return None

    def is_null(self) -> bool:
        """Is null address?"""
        return False

    def is_wildcard(self) -> bool:
        """Wildcard address, not a real one"""
        return False

    def is_multicast(self) -> bool:
        """Is multicast or broadcast address?"""
        return False

    def is_hardware(self) -> bool:
        """Is hardware address?"""
        return False

    def is_global(self) -> bool:
        """Is global address?"""
        return False

    def change_host(self, _host: 'AnyAddress') -> Self:
        """Change host to given address. As default, returns this address"""
        return self

    def priority(self) -> int:
        """Priority of addresses, if choosing one to use"""
        return 0

    def get_parseable_value(self) -> str:
        """Get value which can be unambigiously parsed"""
        return str(self)

    def __lt__(self, other):
        return self.__repr__() < other.__repr__()


class PseudoAddress(AnyAddress):
    """Pseudo-address"""
    def __init__(self, name: str, wildcard=False, multicast=False, hardware=False):
        self.name = name
        self.wildcard = wildcard
        self.multicast = multicast
        self.hardware = hardware

    def is_global(self) -> bool:
        return False

    def is_wildcard(self) -> bool:
        return self.wildcard

    def is_multicast(self) -> bool:
        return self.multicast

    def is_hardware(self) -> bool:
        return self.hardware

    def priority(self) -> int:
        return 3

    def __repr__(self):
        return self.name


class Addresses:
    """Address constants and utilities"""

    # Wildcard for any address
    ANY = PseudoAddress("*", wildcard=True)

    # Pseudo address for BLE advertisement
    BLE_Ad = PseudoAddress("BLE_Ad", multicast=True, hardware=True)

    @classmethod
    def get_prioritized(cls, addresses: Iterable[AnyAddress]) -> AnyAddress:
        """Get prioritized address"""
        add = None
        for a in addresses:
            if add is None or add.priority() < a.priority():
                add = a
        return add or IPAddresses.NULL

    @classmethod
    def parse_address(cls, address: str) -> AnyAddress:
        """Parse any address type from string, type given as 'type/address'"""
        v, _, t = address.rpartition("|")
        if v == "":
            t, v = "ip", t  # default is IP
        if t == "ip":
            return IPAddress.new(v)
        if t == "hw":
            return HWAddress.new(v)
        if t == "name":
            return DNSName(v)
        raise ValueError(f"Unknown address type '{t}', allowed are 'ip', 'hw', and 'name'")

    @classmethod
    def parse_endpoint(cls, value: str) -> AnyAddress:
        """Parse address or endpoint"""
        a, _, p = value.partition("/")
        addr = cls.parse_address(a)
        if p == "":
            return addr
        prot, _, port = p.partition(":")
        if port == "":
            return EndpointAddress(addr, Protocol.get_protocol(prot), -1)
        return EndpointAddress(addr, Protocol.get_protocol(prot), int(port))


class HWAddress(AnyAddress):
    """Hardware address, e.g. Ethernet"""
    def __init__(self, data: str):
        self.data = data.lower()
        assert len(self.data) == 17, f"Expecting HW address syntax dd:dd:dd:dd:dd:dd, got {data}"

    @classmethod
    def new(cls, data: str) -> 'HWAddress':
        """New address, check something about the format"""
        p = list(data.split(":"))
        if len(p) != 6:
            raise ValueError(f"Bad HW address '{data}'")
        for i in range(6):
            if len(p[i]) != 2:
                p[i] = f"0{p[i]}"  # zero-prefix
        return HWAddress(":".join(p))

    @classmethod
    def from_ip(cls, address: 'IPAddress') -> 'HWAddress':
        """Create testing HW address for IP address"""
        a = "40:00:" + ":".join(f"{b:02x}" for b in address.data.packed[-4:])
        return HWAddress(a)

    def get_hw_address(self) -> Optional['HWAddress']:
        return self

    def is_null(self) -> bool:
        return self.data == HWAddresses.NULL.data

    def is_multicast(self) -> bool:
        return self.data == HWAddresses.BROADCAST.data

    def is_hardware(self) -> bool:
        return True

    def priority(self) -> int:
        return 1 if not self.is_multicast() else 11

    def get_parseable_value(self) -> str:
        return f"{self.data}|hw"

    def __eq__(self, other):
        if not isinstance(other, HWAddress):
            return False
        return self.data == other.data

    def __hash__(self):
        return self.data.__hash__()

    def __repr__(self):
        return self.data


class HWAddresses:
    """HW address constants"""

    NULL = HWAddress("00:00:00:00:00:00")

    BROADCAST = HWAddress("ff:ff:ff:ff:ff:ff")


class IPAddress(AnyAddress):
    """IP address, either IPv4 or IPv6"""
    def __init__(self, data: Union[IPv4Address, IPv6Address]):
        self.data = data

    def get_ip_address(self) -> Optional['IPAddress']:
        return self

    @classmethod
    def new(cls, address: str) -> 'IPAddress':
        """Create new IP address"""
        return IPAddress(ipaddress.ip_address(address))

    @classmethod
    def parse_with_port(cls, address: str, default_port=0) -> Tuple['IPAddress', int]:
        """Parse IPv4 address, possibly with port"""
        ad, _, p = address.partition(":")
        return cls.new(ad), default_port if p == "" else int(p)

    def is_null(self) -> bool:
        return self.data == IPAddresses.NULL.data

    def is_multicast(self) -> bool:
        return self.data.is_multicast or self.data == IPAddresses.BROADCAST.data

    def is_global(self) -> bool:
        return self.data.is_global

    def priority(self) -> int:
        return 2

    def get_parseable_value(self) -> str:
        return f"{self.data}"  # IP is the default

    def __eq__(self, other):
        if not isinstance(other, IPAddress):
            return False
        return self.data == other.data

    def __hash__(self):
        return self.data.__hash__()

    def __repr__(self):
        return str(self.data)


class IPAddresses:
    """IP address constants"""

    NULL = IPAddress.new("0.0.0.0")

    BROADCAST = IPAddress.new("255.255.255.255")


class DNSName(AnyAddress):
    """DNS name"""
    def __init__(self, name: str):
        self.name = name

    def is_global(self) -> bool:
        return True  # well, perhaps a flag for this later

    def is_multicast(self) -> bool:
        return False

    def priority(self) -> int:
        return 3

    def get_parseable_value(self) -> str:
        return f"{self.name}|name"

    def __eq__(self, other):
        if not isinstance(other, DNSName):
            return False
        return self.name == other.name

    def __hash__(self):
        return self.name.__hash__()

    def __repr__(self):
        return self.name

    @classmethod
    def name_or_ip(cls, value: str) -> Union[IPAddress, 'DNSName']:
        """Get value as DNS name or IP address"""
        try:
            return IPAddress.new(value)
        except ValueError:
            return DNSName(value)

    @classmethod
    def looks_like(cls, name: str) -> bool:
        """Does the given name look like DNS domain name?"""
        if '.' not in name:
            return False
        for c in name:
            if c != '.' and c != ':' and not ('0' <= c <= '9'):  # pylint: disable=superfluous-parens
                return True  # nost just numbers, good enough for this check
        return False  # only numbers and dots


class EndpointAddress(AnyAddress):
    """Endpoint address made up from host, protocol, and port"""
    def __init__(self, host: AnyAddress, protocol: Protocol, port=-1):
        self.host = host
        self.protocol = protocol
        self.port = port

    @classmethod
    def any(cls, protocol: Protocol, port: int) -> 'EndpointAddress':
        """Shortcut to create wildcard-address endpoint"""
        return EndpointAddress(Addresses.ANY, protocol, port)

    @classmethod
    def ip(cls, ip_address: str, protocol: Protocol, port: int) -> 'EndpointAddress':
        """Shortcut to create IP-address endpoint"""
        return EndpointAddress(IPAddress.new(ip_address), protocol, port)

    @classmethod
    def hw(cls, hw_address: str, protocol: Protocol, port: int) -> 'EndpointAddress':
        """Shortcut to create HW-address endpoint"""
        return EndpointAddress(HWAddress.new(hw_address), protocol, port)

    def get_ip_address(self) -> Optional[IPAddress]:
        return self.host.get_ip_address()

    def get_hw_address(self) -> Optional[HWAddress]:
        return self.host.get_hw_address()

    def get_host(self) -> Optional[AnyAddress]:
        return self.host

    def get_protocol_port(self) -> Optional[Tuple[Protocol, int]]:
        return self.protocol, self.port

    def change_host(self, host: 'AnyAddress') -> Self:
        return EndpointAddress(host, self.protocol, self.port)

    def is_null(self) -> bool:
        return self.host.is_null()

    def is_multicast(self) -> bool:
        return self.host.is_multicast()

    def is_global(self) -> bool:
        return self.host.is_global()

    def is_wildcard(self) -> bool:
        return self.host.is_wildcard()

    def priority(self) -> int:
        return self.host.priority() + 1

    def get_parseable_value(self) -> str:
        port = f":{self.port}" if self.port >= 0 else ""
        prot = f"/{self.protocol.value}" if self.protocol != Protocol.ANY else ""
        return f"{self.host.get_parseable_value()}{prot}{port}"

    def __eq__(self, other):
        if not isinstance(other, EndpointAddress):
            return False
        return self.host == other.host and self.protocol == other.protocol and self.port == other.port

    def __hash__(self):
        return self.host.__hash__() ^ self.protocol.__hash__() ^ self.port

    @classmethod
    def protocol_port_string(cls, value: Optional[Tuple[Protocol, int]]) -> str:
        """Get string value for protocol:port, omit port if value <0"""
        if value is None:
            return ""
        return f"{value[0].value}:{value[1]}" if value[1] >= 0 else f"{value[0].value}"

    def __repr__(self):
        port = f":{self.port}" if self.port >= 0 else ""
        prot = f"/{self.protocol.value}" if self.protocol != Protocol.ANY else ""
        return f"{self.host}{prot}{port}"


class PathAddress(AnyAddress):
    """Address and a path"""
    def __init__(self, origin: AnyAddress, path: str):
        self.origin = origin
        self.path = path

    def get_ip_address(self) -> Optional[IPAddress]:
        return self.origin.get_ip_address()

    def get_hw_address(self) -> Optional[HWAddress]:
        return self.origin.get_hw_address()

    def get_host(self) -> Optional[AnyAddress]:
        return self.origin.get_host()

    def get_origin(self) -> AnyAddress:
        return self.origin

    def get_protocol_port(self) -> Optional[Tuple[Protocol, int]]:
        return self.origin.get_protocol_port()

    def change_host(self, host: 'AnyAddress') -> Self:
        return PathAddress(self.origin.change_host(host), self.path)

    def is_null(self) -> bool:
        return self.origin.is_null()

    def is_multicast(self) -> bool:
        return self.origin.is_multicast()

    def is_global(self) -> bool:
        return self.origin.is_global()

    def is_wildcard(self) -> bool:
        return self.origin.is_wildcard()

    def priority(self) -> int:
        return self.origin.priority() + 1

    def __eq__(self, other):
        if not isinstance(other, PathAddress):
            return False
        return self.origin == other.origin and self.path == other.path

    def __hash__(self):
        return self.origin.__hash__() ^ self.path.__hash__()

    def __repr__(self):
        return f"{self.origin}//{self.path}"
