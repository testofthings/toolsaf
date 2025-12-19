"""Address range matching"""

from ipaddress import IPv4Address
from typing import List, Optional, Tuple

from toolsaf.common.address import AnyAddress, IPAddress


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
                if not (0 <= octet <= 255):
                    raise ValueError(f"Invalid octet in address range: '{part}'")
                range_parts.append((octet, octet))
        return cls(range_parts)        

    def is_match(self, address: AnyAddress) -> bool:
        """Check if address matches the range"""
        match address:
            case IPAddress() if len(self.parts) == 4 and isinstance(address.data, IPv4Address):
                for i, octet in enumerate(address.data.packed):
                    if not (self.parts[i][0] <= octet <= self.parts[i][1]):
                        return False
                return True
        return False

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

    def __repr__(self) -> str:
        return f"Multicast: {self.fixed_address or self.address_range}"