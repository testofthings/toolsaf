"""Common Pydantic field types"""
from typing import Annotated, Iterable
from pydantic import Field, AfterValidator

from toolsaf.common.address import Addresses
from toolsaf.common.property import PropertyKey


NETWORK_ADDRESS_PREFIX = "network="


def validate_upload_tag(tag: str) -> str:
    """Validate an upload tag. Can raise ValueError"""
    if not 3 <= len(tag) <= 50:
        raise ValueError("Upload tag must be between 3 and 50 characters")
    if not all(c.isalnum() or c == "-" for c in tag):
        raise ValueError("Tag can only include alphanumeric characters and hyphens")
    return tag


def validate_address(address: str) -> str:
    """Validate an Address"""
    Addresses.parse_system_address(address) # Raises ValueError if not a proper address
    return address


def validate_network_address(address: str) -> str:
    """Validate a Network address, e.g. 'network=local'"""
    if not address.startswith(NETWORK_ADDRESS_PREFIX):
        raise ValueError(f"Network address must start with '{NETWORK_ADDRESS_PREFIX}'")
    name = address.removeprefix(NETWORK_ADDRESS_PREFIX)
    if not 1 <= len(name) <= 100:
        raise ValueError("Network name must be between 1 and 100 characters")
    return address


def validate_property_keys(properties: Iterable[str]) -> None:
    """Validate all PropertyKeys"""
    try:
        for prop in properties:
            if len(prop) > 100:
                raise ValueError("Property key too long")
            PropertyKey.parse(prop)
    except Exception as e:
        raise ValueError("Incorrect property key format") from e


LongNameType = Annotated[str, Field(..., min_length=1, max_length=300)]
NameType = Annotated[str, Field(..., min_length=1, max_length=100)]
DescriptionType = Annotated[str, Field("", min_length=0, max_length=4000)]
MatchPriorityType = Annotated[int, Field(..., ge=0, le=10)]
SystemAddressType = Annotated[str, AfterValidator(validate_address)]
UploadTagType = Annotated[str, AfterValidator(validate_upload_tag)]
NetworkAddressType = Annotated[str, AfterValidator(validate_network_address)]

SourceIdType = Annotated[str, Field(min_length=3, max_length=20, pattern=r"^id\d+$", strict=True)]
