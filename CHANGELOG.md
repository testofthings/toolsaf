# Changelog
## 0.9.0
### Added
- Entities can be renamed with `name()` without changing their system address.
- Entities can be removed with `system.remove_entity(entity)` and `system.remove_network(network)`.
- Host addresses can be replaced with `set_addresses()`.
- Batch data files of HAR, SPDX, and Black Duck can be named by the entity tag, which does not change when the entity is renamed.
- SPDX and Black Duck data files can be named by software and host tags, e.g. `FW@Device_1.json`. A data file name matching multiple entities is an error.
- Added a new `generic` tool adapter for reading verdicts and properties of entities from a generic JSON format.
- Non-default networks are now (de)serialized.

### Changed
- The default network name is now `default` instead of `local`. Legacy network addresses with or without the `network=` prefix are still accepted.
- Creating two networks with the same name produces an error.
- Creating a host whose tag is used by another host produces an error, e.g. `device("A B")` and `device("A_B")`.
- All host addresses are shown in the output, tag first. Address prioritization is now consistent and deterministic.
- `CertMITMReader` assigns MITM failures to the target TLS service instead of the connection, and sets the TLS best practices property of the service.
- Verdicts and properties of entities are no longer (de)serialized with the statement.
- Change serialization order is now removals first, then parents before children.
- Events of removed entities are skipped when loading a statement.
- Software component names can be up to 200 characters long.
- Network masks are validated, and loopback always has the well-known mask.

### Fixed
- Fixed traffic matching corner cases: flows with the same source and target are now ignored, multicasts and broadcasts are detected by their Ethernet address, and unexpected services in expected hosts are matched properly.
- System addresses of entities were not always unique, e.g. when a free entity name was picked without considering tags. System addresses are now checked for uniqueness.
- Ignore rules were not applied in some cases, fixed.
- Custom services did not honor the given networks, fixed.
- Some edits to loaded statements were not marked as changes, fixed.

### Documentation
- Added [Editing loaded statements](documentation/EditingStatements.md) and data file naming instructions to `Tools.md`. Fixed `Ssh-audit` and `Testssl.sh` file name templates.

## 0.8.1
### Fixed
- Toolsaf was not able to properly parse .pcap files / packets that were missing ethernet frames, fixed.
- The adapters `AndroidManifestScan`, `ShodanScan`, `SPDXReader`, and `ZEDReader` were missing explanations from some of the events they produced, fixed.

## 0.8.0
### Changed
- **Minimum Python version bumped to 3.12.** This is required because our dependency, [packet-framing](https://github.com/testofthings/packet-framing), now relies on typing features introduced in Python 3.12.

## 0.7.1
### Added
- It is now possible to mark MQTT connections as encrypted through the DSL `MQTT(tls=True)`

### Fixed
- `CertMITMReader` adapter was not able to assign `PASS` verdicts based on certificates with an IP address in their name, fixed.
- `CertMITMReader` would only assign `PASS` verdicts to connections with the `TLS` protocol. It now assigns based on `ConnectionType`.

### Documentation
- Added an example on how to collect data with `ssh-audit` running a Docker container

## 0.7.0
### Added
- Made deserialized statements editable. This feature can be used through `system = Builder.load("<file_path>")`
- Added a new lazy loading statement deserialization variant, `SystemSerializer.deserialize_list()`, to support the deserialization of out-of-order statement data.
- Multiple DNS names can now be supplied to a single `dns()` call, e.g. `backend.dns("example.com", "example.org")`
- Re-added `Network` serialization. However, only an `IoTSystem's` local `Network` is (de)serialized

### Fixed
- It was possible to create security statements where multiple entities had the same system address. Known cases fixed.
- Documentation stated that address ranges and wildcards were usable with `multicast()`. This was actually not the case, fixed!
- Software components provided with `sbom()` and Android mobile application permissions supplied with `set_permissions` were not displayed by default when running statements. Now they are always displayed.
- Explanations for failure verdicts created by the `SPDXReader` adapter were not descriptive at all, now they are.

### Documentation
- Updated `Tools.md` instructions on Android Manifest files, nmap and Shodan scanning.
- Updated instructions on `NodeComponentTool` tool data file naming conventions.

## 0.6.0
- Replaced the `SerializerStream`-based security statement (de)serialization approach with the new `SystemSerializer` and `EventSerializer`. Deserialization now utilizes Pydantic.
- Security statement JSON format version updated from `1.0` to `2.0`. Version `1.0` serialized statements cannot be deserialized with Toolsaf `0.6.0`. Statements must be reserialized to the new format.
- Changes to (de)serialized data include:
    - `id` removed.
    - `at` (ID denoting parent entity) replaced with `parent_address` (system address).
    - Connection `source` (ID) replaced with `source_address` (system address).
    - Connection `target` (ID) replaced with `target_address` (system address).
    - Connection `properties` and `con_type` are now serialized and deserialized.
    - Connection `source_long_name`, `target_long_name` and `tag` removed.
    - EvidenceSource `source-id` renamed to `source_id`, `ref` renamed to `tail_ref`.
    - and so on...

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
