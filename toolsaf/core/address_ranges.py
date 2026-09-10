"""Address range matching"""

from ipaddress import IPv4Address
from typing import List, Optional, Tuple, Any
from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

from toolsaf.common.address import Addresses, AnyAddress, IPAddress


class AddressRange:
    """Address range"""
    def __init__(self, parts: List[Tuple[int, int]]) -> None:
        self.parts = parts

    @classmethod
    def parse_range(cls, specification: str, delimiter: str = ".") -> 'AddressRange':
        """Parse address range with * as wildcard matching any octet"""

        # pylint: disable=raise-missing-from

        # Delimiter '.' is used for IPv4 addresses
        parts = specification.split(delimiter)
        if len(parts) != 4:
            raise ValueError(f"Expected 4-part address, got '{specification}'")
        range_parts: List[Tuple[int, int]] = []
        for part in parts:
            if part == "*":
                range_parts.append((0, 255))
            elif "-" in part:
                start_str, end_str = part.split("-", 1)
                try:
                    start, end = int(start_str), int(end_str)
                except ValueError:
                    raise ValueError(f"Non-integer in segment '{part}' in '{specification}'")
                if not (0 <= start <= 255 and 0 <= end <= 255) or start > end:
                    raise ValueError(f"Invalid segment '{part}' in '{specification}'")
                range_parts.append((start, end))
            else:
                try:
                    octet = int(part)
                except ValueError:
                    raise ValueError(f"Non-integer in segment '{part}' in '{specification}'")
                if not 0 <= octet <= 255:
                    raise ValueError(f"Invalid segment '{part}' in '{specification}'")
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
    def __init__(self, fixed_addresses: Optional[List[AnyAddress]] = None,
                 address_range: Optional[AddressRange] = None) -> None:
        assert (not fixed_addresses) != (address_range is None), \
            "Either fixed_addresses or range must be provided"
        self.fixed_addresses = fixed_addresses or []
        self.address_range = address_range

    def is_match(self, address: AnyAddress) -> bool:
        """Check if address matches here"""
        if self.fixed_addresses:
            return address in self.fixed_addresses
        if self.address_range is not None:
            return self.address_range.is_match(address)
        return False

    def get_parseable_value(self) -> str:
        """Get parseable value"""
        if self.fixed_addresses:
            return ",".join(a.get_parseable_value() for a in self.fixed_addresses)
        if self.address_range:
            return repr(self.address_range)
        return ""

    @classmethod
    def from_specs(cls, specs: List[str]) -> 'MulticastTarget':
        """Build from one or more address specs, each either fixed or a wildcard range"""
        if len(specs) == 1 and ("*" in specs[0] or "-" in specs[0]):
            return cls(address_range=AddressRange.parse_range(specs[0]))
        return cls(fixed_addresses=[Addresses.parse_address(s) for s in specs])

    @classmethod
    def parse_address_range(cls, address_range: str) -> 'MulticastTarget':
        """Parse multicast target from a comma-separated list of address specs (wire format)"""
        return cls.from_specs(address_range.split(","))

    def __hash__(self) -> int:
        return hash((tuple(self.fixed_addresses), self.address_range))

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, MulticastTarget):
            return False
        return (self.fixed_addresses == value.fixed_addresses and
                self.address_range == value.address_range)

    def __repr__(self) -> str:
        return f"Multicast: {', '.join(str(a) for a in self.fixed_addresses) or self.address_range}"

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler # pylint: disable=unused-argument
    ) -> core_schema.CoreSchema:
        """Pydantic schema for MulticastTarget"""
        return core_schema.no_info_after_validator_function(
            cls.parse_address_range,
            core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda r: r.get_parseable_value(),
                info_arg=False,
                return_schema=core_schema.str_schema()
            )
        )


class PortRange:
    """Port range"""
    def __init__(self, ranges: List[Tuple[int, int]]) -> None:
        # Check that ranges are valid and non-overlapping
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

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler # pylint: disable=unused-argument
    ) -> core_schema.CoreSchema:
        """Pydantic schema for PortRange"""
        return core_schema.no_info_after_validator_function(
            cls.parse_port_range,
            core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda r: r.get_parseable_value(),
                info_arg=False,
                return_schema=core_schema.str_schema()
            )
        )


# Null range
NULL_PORT_RANGE = PortRange([])
