# Changelog
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
