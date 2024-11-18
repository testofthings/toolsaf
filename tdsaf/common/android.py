"""Android permisison definitions"""

import enum


class MobilePermissions(enum.Enum):
    """Android manifest.xml permission categories.
       Categories based on https://m2.material.io/design/platform-guidance/android-permissions.html#usage"""
    PHONE = "Phone"                    # Make and manage calls
    LOCATION = "Location"              # Access to current device location
    STORAGE = "Storage"                # Access to photos, media and files
    NETWORK = "Network"                # Access to networks and WiFi configs
    ADMINISTRATIVE = "Administrative"  # Device administration and security
    SMS = "SMS"                        # Access to SMS and messaging
    SETTINGS = "Settings"              # Access to system settings and cofigs
    BLUETOOTH = "Bluetooth"            # Bluetooth and device management
    ACCOUNT = "Account"                # User account and authentication
    RECORDING = "Recording"            # Access to camera and microphone

    UNCATEGORIZED = "Uncategorized"    # What to do with this one?
