"""Some basic definitions"""

import enum


class HostType(enum.Enum):
    """Host types"""
    GENERIC = ""               # default, assumed plaintext data
    DEVICE = "Device"          # local device
    MOBILE = "Mobile"          # mobile (application)
    REMOTE = "Remote"          # remote, youngsters call it "cloud"
    BROWSER = "Browser"        # browser, user selected and installed
    ADMINISTRATIVE = "Admin"   # administration, match ConnectionType


class ConnectionType(enum.Enum):
    """Connection types"""
    UNKNOWN = ""               # default, assumed plaintext data
    ENCRYPTED = "Encrypted"    # strong encryption
    ADMINISTRATIVE = "Admin"   # administration, no private data
    LOGICAL = "Logical"        # only a logical connection


class ExternalActivity(enum.IntEnum):
    """External activity levels"""
    BANNED = 0                 # no external activity allowed
    PASSIVE = 1                # passive, probing ok but no replies
    OPEN = 2                   # external use of open services ok
    UNLIMITED = 3              # unlimited activity, including client connections


class Status(enum.Enum):
    """Entity status"""
    PLACEHOLDER = "Placeholder"    # Placeholder for unexpected or external entity
    EXPECTED = "Expected"          # Expected entity
    UNEXPECTED = "Unexpected"      # Unexpected entity
    EXTERNAL = "External"          # External entity
