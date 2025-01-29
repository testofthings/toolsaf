# Tool Adapters

[Architecture root](README.md)

This document provides information on the contents of the [adapters](../../toolsaf/adapters/) directory.

## Adapter Base Classes

### File [tools.py](../../toolsaf/adapters/tools.py).

Parent of all the other tool adapter base classes.

Notable variables:
| Variable   | Description  |
|:----------:|:-------------|
| `data_file_suffix` | File type accepted by the tool |
| `system`           | IoTSystem |
| `send_events`      | Should events be logged to the database. Default `True` |
| `load_baseline`    | **FIXME**. Default `False`. Read from `00meta.json` |

---
### `SystemWideTool`

The tool data processed by SystemWideTools includes all the addresses/info necessary for output analysis, e.g. IP addresses, DNS names, and ports. The output of a SystemWideTool is applied to the `system` as indicated by the provided tool output.

**Input file name:** Any name.

---
### `EndpointTool`

EndpointTool applies tool output to specific endpoints. Endpoints are specified in tool outputs' file names. For example, a file called Mobile_App.xml would apply produced results to the system's endpoint named Mobile_App.

**Input file name:** File must be named _address_ + `data_file_suffix`, where _address_ can be an address tag from `00meta.json`, an IP address, or a DNS name.

### `NetworkNodeTool`

Tool output applied to network nodes.

**Input file name:** Files must be named after hosts' tag addresses. For example, `Browser` + `data_file_suffix`.

---
### `NodeComponentTool`

NodeComponentTool applies tool output to node components.

**Input file name:** Sample data files need to be named after components. For example, if we want to apply tool output to Mobile_App's SW component, the file name must be Mobile_App_SW + `data_file_suffix`

---
## Writing new tool adapters

A _tool adapter_ reads tool result files and sends [`Event`s](Common.md#file-trafficpy) to update the model and give verdicts.
A tool adapter must never directly set a property,
but properties are carried from tool adapters into entities by the Events.
This ensures that the evidence for each property change is logged properly.

A new tool adapter must be derived from the appropriate base class, listed above.
The selection of the base class depends on how much information is contained in the
tool output, e.g. `SystemWideTool` can direct the output to the proper entity without any help.

FIXME: Not very comprehensive, yet. Use the source!

## Tool Adapters

### AndroidManifestScan
File: [android_manifest_scan.py](../../toolsaf/adapters/android_manifest_scan.py)

Adapter for processing AndroidManifest files in `.xml` format, containing mobile application permissions. Connects permissions to categories based on a JSON file. Verdict `Fail` if permission only present in either Manifest file or statement SBOM.

### CensysScan
File: [censys_scan.py](../../toolsaf/adapters/censys_scan.py)

Adapter for processing Censys scan results in `.json` format.

### CertMITMReader
File: [certmitm_reader.py](../../toolsaf/adapters/certmitm_reader.py)

Adapter for processing `zip` compressed certmitm output folders. Creates flows with verdict `Fail` between sources and targets in tool output.

### HARScan
File: [har_scan.py](../../toolsaf/adapters/har_scan.py)

Adapter for processing HAR files in `.json` format extracted from Browser.

### NMAPScan
File: [nmap_scan.py](../../toolsaf/adapters/nmap_scan.py)

Adapter for processing nmap results in `.xml` format.

### PCAPReader
File: [pcap_reader](../../toolsaf/adapters/pcap_reader.py)

Adapter for processing tcpdump or Wireshark packet captures in `.pcap` format.

### PingCommand
File: [ping_command.py](../../toolsaf/adapters/ping_command.py)

Adapter for processing ping command results.

### GithubReleaseReader
File: [github_releases.py](../../toolsaf/adapters/github_releases.py)

Adapter for processing release information. **Experimental.**

### ShodanScan
File: [shodan_scan.py](../../toolsaf/adapters/shodan_scan.py)

Adapter for processing Shodan scan results in `.json` format.

### SimpleFlowTool
File: [tools.py](../../toolsaf/adapters/tools.py)

Adapter for reading JSON flows.

### SPDXReader
File: [spdx_reader.py](../../toolsaf/adapters/spdx_reader.py)

Adapter for processing SPDX format SBOM `.json` files created with a sbom generator.

### SSHAuditScan
File: [ssh_audit_scan.py](../../toolsaf/adapters/ssh_audit_scan.py)

Adapter for processing ssh-audit results in `.json` format.

### TestSSLScan
File: [testsslsh_scan.py](../../toolsaf/adapters/testsslsh_scan.py)

Adapter for processing testssl results in `.json` format.

### TSharkReader
File: [tshark_reader.py](../../toolsaf/adapters/tshark_reader.py)

Adapter for processing TShark BLE capture results in `.json` format.

### VulnerabilityReader
File: [vulnerability_reader.py](../../toolsaf/adapters/vulnerability_reader.py)

Adapter for processing BlackDuck binary analysis results in `.csv` format.

### WebChecker
File: [web_checker.py](../../toolsaf/adapters/web_checker.py)

Adapter for processing `.http` files created with `curl`. Assigns result to system's `OnlineResources`.

### ZEDReader
File: [zed_reader.py](../../toolsaf/adapters/zed_reader.py)

Adapter for processing ZED Attack Proxy results in `.json` format.

## FIXME
- SetupCSVReader
- ToolDepiction
- ToolFinderImplementation
- BatchImporter