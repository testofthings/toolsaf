"""Android permisison definitions"""
#pylint: disable=invalid-name

import enum

class MobilePermissions(enum.Enum):
    """Android manifest.xml permission categories.
       Categories based on https://m2.material.io/design/platform-guidance/android-permissions.html#usage"""
    CALLS = "Calls"                    # Make and manage calls
    SMS = "SMS"                        # Access to SMS and messaging
    CONTACTS = "Contacts"              # Access to contact information
    CALENDAR = "Calendar"              # Access to user's calendar
    LOCATION = "Location"              # Access to current device location
    RECORDING = "Recording"            # Access to camera and microphone
    STORAGE = "Storage"                # Access to photos, media and files
    NETWORK = "Network"                # Access to networks and WiFi configs
    HEALTH = "Health"                  # Access to body sensors, biometrics, ...
    ACCOUNT = "Account"                # User account and authentication
    BILLING = "Billing"                # Has in-app purchases
    BLUETOOTH = "Bluetooth"            # Bluetooth and device management
    ADMINISTRATIVE = "Administrative"  # Device administration and security

    UNCATEGORIZED = "Uncategorized"    # What to do with this one?

CALLS = MobilePermissions.CALLS
"""Make and manage calls"""

SMS = MobilePermissions.SMS
"""Read/write messages"""

CONTACTS = MobilePermissions.CONTACTS
"""Access to contact information"""

CALENDAR = MobilePermissions.CALENDAR
"""Access to user's calendar"""

LOCATION = MobilePermissions.LOCATION
"""Access to device location"""

RECORDING = MobilePermissions.RECORDING
"""Access to camera and/or microphone"""

STORAGE = MobilePermissions.STORAGE
"""Read and write data on the mobile device"""

NETWORK = MobilePermissions.NETWORK
"""Access to network configurations"""

HEALTH = MobilePermissions.HEALTH
"""Access to body sensors, biometrics, ..."""

ACCOUNT = MobilePermissions.ACCOUNT
"""Access to user account and authenticatio"""

BILLING = MobilePermissions.BILLING
"""Has in-app purchases"""

BLUETOOTH = MobilePermissions.BLUETOOTH
"""Access to bluetooth and nearby device management"""

ADMINISTRATIVE = MobilePermissions.ADMINISTRATIVE
"""Access to device administration and security"""

UNCATEGORIZED = MobilePermissions.UNCATEGORIZED
"""Uncategorized permissions"""
