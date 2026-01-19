# Changelog

## 0.5.0
- Added new host type `multicast` to explicitly stand for entities which listen for multicasts or broadcast
  outside the security statement
- Updated address matching logic
- Experimental command-line switch `-m 2` to enable more strict matching for local connections, they must now
  always be defined in security statement

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
