# Architecture

## NetworkNode
- Should have no more than 1 software component.

## Common
This section provides info on `tdsaf.common`.

FIXME

## Core
This section provides info on `tdsaf.core`.

FIXME

## Tools
This section provides info on the various tool classes and finders, batch directory importer and tool output readers. These are all found under `tdsaf.adapters`.

### Base Classes
#### **ToolAdapter**
- File: [Tools.py](../tdsaf/adapters/tools.py).
- Base class for the various tool types.

#### **SetupCSVReader**.
- File: [setup_reader.py](../tdsaf/adapters/setup_reader.py)
- Reads setup documentation CSV files.
- FIXME.

#### **SystemWideTool**
- File: [Tools.py](../tdsaf/adapters/tools.py).
- Sample data files contain all the addresses/info needed for output analysis.
  - IP addresses, DNS names, ports, etc.
- Applies tool output to system as indicated by the output.

#### **SimpleFlowTool**
- File: [Tools.py](../tdsaf/adapters/tools.py).
- Child of **SystemWideTool**.
- JSON flow reader.

#### **EndpointTool**
- File: [Tools.py](../tdsaf/adapters/tools.py).
- Tool output applied to specific endpoints.
- Sample data file name should be AnyAddress + .file extension.
  - AnyAddress can be addresses tag (00meta.json), IP address or DNS name.
  - e.g. `Mobile_App.xml`.
- If node is not of correct HostType raises ConfigurationException.
- Node should have exctly one software component.

#### **NetworkNodeTool**
- File: [Tools.py](../tdsaf/adapters/tools.py).
- Tool output applied to network nodes.
- FIXME

#### **NodeComponentTool**
- File: [Tools.py](../tdsaf/adapters/tools.py).
- Tool output applied to node components.
- Sample data file name needs to be the same as the components.
  - For example SW component with name "App SW" connects to data file `App_SW.json`

---
### Tool Finder
File: [tool_finder.py](../tdsaf/adapters/tool_finder.py).

FIXME

---
### Batch Import
File: [batch_import.py](../tdsaf/adapters/batch_import.py).

Loads sample data from a batch directory.

FIXME

---
### Tool Output Readers
#### **AndroidManifestScan**
- File: [android_manifest_scan.py](../tdsaf/adapters/android_manifest_scan.py).
- Is an EndpointTool.
- Reads permissions from Android Manifest `.xml` files, connects them to categories and assigns the relevant categories to mobile node's SW components.
- Sets verdict to `PASS` if permission is in both statement and manifest file; `FAIL` otherwise.
- Uses [json file](../tdsaf/adapters/data/android_permissions.json) contents to connect permisisons to categories.

#### **CensysScan**
- File: [censys_scan.py](../tdsaf/adapters/censys_scan.py).
- Is an EndpointTool.
- FIXME

#### **CertMITMReader**
- File: [certmitm_reader.py](../tdsaf/adapters/certmitm_reader.py).
- Is a SystemWideTool.
- Reads `zip` compressed [certmitm](https://github.com/aapooksman/certmitm) outputs, creates flows with verdict `FAIL` between connection source and target.
- Result assigned to MITM property.

#### **HARScan**
- File: [har_scan.py](../tdsaf/adapters/har_scan.py).
- Is a NetworkNodeTool.
- FIXME

#### **MITMLogReader**
- File: [mitm_log_reader.py](../tdsaf/adapters/mitm_log_reader.py).
- Is a SystemWideTool.
- FIXME

#### **NMAPScan**
- File: [nma_scan.py](../tdsaf/adapters/nmap_scan.py).
- Is a SystemWideTool.
- FIXME

#### **PCAPReader**
- File: [pcap_reader](../tdsaf/adapters/pcap_reader.py).
- Is a SystemWideTool.
- FIXME

#### **PingCommand**
- File: [ping_command.py](../tdsaf/adapters/ping_command.py).
- Is a SystemWideTool.
- FIXME

#### **ReleasesReader**
- File: [releases.py](../tdsaf/adapters/releases.py).
- Is a NodeComponentTool.
- FIXME

#### **ShellCommandPs**
- File: [shell_commands.py](../tdsaf/adapters/shell_commands.py).
- Is an EndpointTool.
- FIXME

#### **SPDXReader**
- File: [spdx_reader.py](../tdsaf/adapters/spdx_reader.py).
- Is a NodeComponentTool.
- FIXME

#### **SSHAuditScan**
- File: [ssh_audit_scan.py](../tdsaf/adapters/ssh_audit_scan.py).
- Is an EndpointTool.
- FIXME

#### **TestSSLScan**
- File: [testsslsh_scan.py](../tdsaf/adapters/testsslsh_scan.py).
- Is an EndpointTool.
- FIXME

#### **TSharkReader**
- File: [tsrahk_reader.py](../tdsaf/adapters/tshark_reader.py).
- Is a SystemWideTool.
- FIXME

#### **VulnerabilityReader**
- File: [vulnerability_reader.py](../tdsaf/adapters/vulnerability_reader.py).
- Is a NodeComponentTool.
- FIXME

#### **WebChecker**
- File: [web_checker.py](../tdsaf/adapters/web_checker.py).
- Is a SystemWideTool.
- FIXME

#### **ZEDReader**
- File: [zed_reader.py](../tdsaf/adapters/zed_reader.py).
- Is a SystemWideTool.
- FIXME

## Exceptions
This section provides info on the custom exceptions in TDSAF.

### ConfigurationException
-Configuration was incorrect.
