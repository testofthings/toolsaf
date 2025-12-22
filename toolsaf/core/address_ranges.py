"""Address range matching"""

from ipaddress import IPv4Address
from typing import List, Optional, Tuple

from toolsaf.common.address import Addresses, AnyAddress, IPAddress


class AddressRange:
    """Address range"""
    def __init__(self, parts: List[Tuple[int, int]]) -> None:
        self.parts = parts

    @classmethod
    def parse_range(cls, specification: str, delimiter: str = ".") -> 'AddressRange':
        """Parse address range with * as wildcard matching any octet"""

        # Delimiter '.' is used for IPv4 addresses
        parts = specification.split(delimiter)
        if len(parts) != 4:
            raise ValueError(f"Invalid address range: '{specification}'")
        range_parts: List[Tuple[int, int]] = []
        for part in parts:
            if part == "*":
                range_parts.append((0, 255))
            else:
                octet = int(part)
                if not 0 <= octet <= 255:
                    raise ValueError(f"Invalid octet in address range: '{part}'")
                range_parts.append((octet, octet))
        return cls(range_parts)

    def is_match(self, address: AnyAddress) -> bool:
        """Check if address matches the range"""
        match address:
            case IPAddress() if len(self.parts) == 4 and isinstance(address.data, IPv4Address):
                for i, octet in enumerate(address.data.packed):
                    if not self.parts[i][0] <= octet <= self.parts[i][1]:
                        return False
                return True
        return False

    def __hash__(self) -> int:
        return hash(tuple(self.parts))

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, AddressRange):
            return False
        return self.parts == value.parts

    def __repr__(self) -> str:
        parts_str = []
        for part in self.parts:
            if part[0] == 0 and part[1] == 255:
                parts_str.append("*")
            elif part[0] == part[1]:
                parts_str.append(str(part[0]))
            else:
                parts_str.append(f"{part[0]}-{part[1]}")
        return ".".join(parts_str)


class MulticastTarget:
    """Multicast target definition"""
    def __init__(self, fixed_address: Optional[AnyAddress] = None,
                 address_range: Optional[AddressRange] = None) -> None:
        assert (fixed_address is None) != (address_range is None), "Either fixed_address or range must be provided"
        self.fixed_address = fixed_address
        self.address_range = address_range

    def is_match(self, address: AnyAddress) -> bool:
        """Check if address matches here"""
        if self.fixed_address is not None:
            return self.fixed_address == address
        if self.address_range is not None:
            return self.address_range.is_match(address)
        return False

    def get_parseable_value(self) -> str:
        """Get parseable value"""
        if self.fixed_address:
            return self.fixed_address.get_parseable_value()
        if self.address_range:
            return repr(self.address_range)
        return ""

    @classmethod
    def parse_address_range(cls, address_range: str) -> 'MulticastTarget':
        """Parse multicast target from address range"""
        if "*" in address_range or "-" in address_range:
            addr_range = AddressRange.parse_range(address_range)
            return cls(address_range=addr_range)
        fixed = Addresses.parse_address(address_range)
        return cls(fixed_address=fixed)

    def __hash__(self) -> int:
        return hash((self.fixed_address, self.address_range))

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, MulticastTarget):
            return False
        return (self.fixed_address == value.fixed_address and
                self.address_range == value.address_range)

    def __repr__(self) -> str:
        return f"Multicast: {self.fixed_address or self.address_range}"


class PortRange:
    """Port range"""
    def __init__(self, ranges: List[Tuple[int, int]]) -> None:
        # Check that ranges are valid and non-overlapping
        if not ranges:
            raise ValueError("Port range cannot be empty")
        self.ranges = ranges
        i = -1
        for ra in ranges:
            start, end = ra
            if start <= i:
                raise ValueError(f"Overlapping or out of order range: {start}-{end}")
            if start > end:
                raise ValueError(f"Invalid port range: start {start} > end {end}")
            i = end

    def __add__(self, other: 'PortRange') -> 'PortRange':
        """Add other port range, must be non-overlapping"""
        new_ranges = self.ranges + other.ranges
        sorted_ranges = sorted(new_ranges, key=lambda r: r[0])
        return PortRange(sorted_ranges)

    def get_low_port(self) -> int:
        """Get lowest port in the range"""
        return self.ranges[0][0]

    def get_high_port(self) -> int:
        """Get highest port in the range"""
        return self.ranges[-1][1]

    def is_match(self, port: int) -> bool:
        """Check if port matches the range"""
        for ra in self.ranges:
            if ra[0] <= port <= ra[1]:
                return True
        return False

    def get_name(self) -> str:
        """Get name for the port range"""
        lo, hi = self.get_low_port(), self.get_high_port()
        if lo == hi:
            return str(lo)
        if len(self.ranges) == 1:
            return f"{lo}-{hi}"  # single range
        return f"{lo}...{hi}" # multiple ranges

    def get_parseable_value(self) -> str:
        """Get parseable value"""
        parts = []
        for ra in self.ranges:
            if ra[0] == ra[1]:
                parts.append(str(ra[0]))
            else:
                parts.append(f"{ra[0]}-{ra[1]}")
        return ",".join(parts)

    @classmethod
    def parse_port_range(cls, port_range: str) -> 'PortRange':
        """Parse port range definition"""
        parts = port_range.split(",")
        ranges: List[Tuple[int, int]] = []
        for part in parts:
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                start, end = int(start_str), int(end_str)
            else:
                start = end = int(part)
            ranges.append((start, end))
        return cls(ranges)

    def __hash__(self) -> int:
        return hash(tuple(self.ranges))

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, PortRange):
            return False
        return self.ranges == value.ranges

    def __repr__(self) -> str:
        return self.get_parseable_value()

# Null range
NULL_PORT_RANGE = PortRange([(0, 0)])
