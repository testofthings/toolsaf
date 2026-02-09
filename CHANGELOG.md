# Changelog

## 0.5.0
- Changed data upload to send the deserialized statement and tool data to different API endpoints.
- Modified security statement event data serialization and deserialization.
- Added `description` and collection `location` information to `EvidenceSources`.
- Added timestamps to `NameEvents`.
- Replaced timezone-naive timestamps with timezone-aware ones.
- Bug fixes:
    - `ports()` and `port_range()` can now be used with `TCP`.
    - `EventSerializer` now uses the correct field when reading the `tail-ref`.

## 0.4.0
- Traffic capture matching code refactored, which may change the interpretation of some PCAPs
- Refactored broadcast and multicast support, changed the notation and added support for address ranges. See documentation for changes, old notation is supported even when it is not mentioned. Broadcasts and multicasts are now identified by Ethernet's i/g-bit.
- Added port ranges for selected protocols, see documentation.
- Bug fixes: CertMITM reader, DNS message parsing
- Changes for verdict and logging logic, this should not affect command-line use.

## 0.3.0
- First automated release

## 0.2.0
- First official version
