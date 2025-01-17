# Tool Adapters
This document provides information the contents of the [adapters](../../toolsaf/adapters/) directory.

## Adapter Base Classes

### ToolAdapter
File: [tools.py](../../toolsaf/adapters/tools.py).

Parent of all the other tool base classes.

Notable variabels:
| Variable   | Description  |
|:----------:|:-------------|
| `data_file_suffix` | File type accepted by the tool |
| `system`           | IoTSystem |
| `send_events`      | Should events be logged to database. Default `True` |
| `load_baseline`    | **FIXME**. Default `False`. Read from `00meta.json` |

---
### SystemWideTool
File: [tools.py](../../toolsaf/adapters/tools.py).

The tool data processed by SystemWideTools include all the addresses/info necessary for output analysis, e.g. IP addresses, DNS names and ports. The output of a SystemWideTool is applied to the `system` as indicated by the provided tool output.

File can have any name.

---
### EndpointTool
File: [tools.py](../../toolsaf/adapters/tools.py).

EndpointTool applies tool output to specific endpoints. Endpoints are specified in tool outputs' file names. For example, a file called Mobile_App.xml would apply produced results to the system's endpoint named Mobile_App.

As such, tool output must be named _AnyAddress_ + `data_file_suffix`. _AnyAddress_ can an address tag from `00meta.json`, and IP address or DNS name.

---
### NetworkNodeTool
File: [tools.py](../../toolsaf/adapters/tools.py).

Tool output applied to network nodes.

Files are named after hosts/nodes in the system. For example, Browser + `data_file_suffix`.

---
### NodeComponentTool
File: [tools.py](../../toolsaf/adapters/tools.py).

NodeComponentTool applies tool output to node components. Sample data files need to be named after components. For example, if we want to apply tool output to Mobile_App's SW component, the file name must be Mobile_App_SW + `data_file_suffix`

---
## Tool Adapters

### AndroidManifestScan
| Property | Details |
|----------|---------|
| File          | [android_manifest_scan.py](../../toolsaf/adapters/android_manifest_scan.py) |
| Base class    | [EndpointTool](#endpointtool) |
| Tool output   | `.xml` format AndroidManifest containing mobile application permissions |
| Verdict `Pass`| If permisison categories set for the mobile application in security statement match tool output |
| Other         | Connects permissions to categories based on this [JSON file](../../toolsaf/adapters/data/android_permissions.json). Result assigned with 'permission' property |

---
### CensysScan
| Property   | Details  |
|:----------:|:---------|
| File          | [censys_scan.py](../../toolsaf/adapters/censys_scan.py) |
| Base class    | [EndpointTool](#endpointtool) |
| Tool output   | `.json` format Censys scan results |
| Verdict `Pass`| **FIXME** |

---
### CertMITMReader
| Property   | Details  |
|:----------:|:---------|
| File          | [certmitm_reader.py](../../toolsaf/adapters/certmitm_reader.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | `zip` compressed certmitm output folders |
| Verdict `Pass`| Never |
| Other         | Creates flows with verdict `Fail` between sources and targets in tool output. Result assigned with `mitm` property |

---
### HARScan
| Property   | Details  |
|:----------:|:---------|
| File          | [har_scan.py](../../toolsaf/adapters/har_scan.py) |
| Base class    | [NetworkNodeTool](#networknodetool) |
| Tool output   | `.json` format HAR files extractred from Browser |
| Verdict `Pass`| **FIXME** |

---
### MITMLogReader
| Property | Details |
|----------|---------|
| File          | [mitm_log_reader.py](../../toolsaf/adapters/mitm_log_reader.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | **FIXME** |
| Verdict `Pass`| **FIXME** |

---
### NMAPScan
| Property   | Details  |
|:----------:|:---------|
| File          | [nmap_scan.py](../../toolsaf/adapters/nmap_scan.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | `.xml` format nmap results |
| Verdict `Pass`| **FIXME** |

---
### PCAPReader
| Property   | Details  |
|:----------:|:---------|
| File          | [pcap_reader](../../toolsaf/adapters/pcap_reader.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | `.pcap` format tcpdump of Wireshark packet caputes |
| Verdict `Pass`| **FIXME** |

---
### PingCommand
| Property   | Details  |
|:----------:|:---------|
| File          | [ping_command.py](../../toolsaf/adapters/ping_command.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | **FIXME** |
| Verdict `Pass`| **FIXME** |

---
### ReleasesReader
| Property   | Details  |
|:----------:|:---------|
| File          | [releases.py](../../toolsaf/adapters/releases.py) |
| Base class    | [NodeComponentTool](#nodecomponenttool) |
| Tool output   | **FIXME** |
| Verdict `Pass`| **FIXME** |

---
### ShellCommandPs
| Property   | Details  |
|:----------:|:---------|
| File          | [shell_commands.py](../../toolsaf/adapters/shell_commands.py) |
| Base class    | [EndpointTool](#endpointtool) |
| Tool output   | **FIXME** |
| Verdict `Pass`| **FIXME** |

---
### ShellCommandSs
| Property   | Details  |
|:----------:|:---------|
| File          | [shell_commands.py](../../toolsaf/adapters/shell_commands.py) |
| Base class    | [EndpointTool](#endpointtool) |
| Tool output   | **FIXME** |
| Verdict `Pass`| **FIXME** |

---
### SimpleFlowTool
| Property   | Details  |
|:----------:|:---------|
| File          | [tools.py](../../toolsaf/adapters/tools.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | **FIXME** |
| Verdict `Pass`| **FIXME** |

---
### SPDXReader
| Property   | Details  |
|:----------:|:---------|
| File          | [spdx_reader.py](../../toolsaf/adapters/spdx_reader.py) |
| Base class    | [NodeComponentTool](#nodecomponenttool) |
| Tool output   | `.json` format SPDX files created with a sbom generator or BlackDuck |
| Verdict `Pass`| If SW node component present in both security statement and batch directory SBOM |
| Other         | To `component` property |

---
### SSHAuditScan
| Property   | Details  |
|:----------:|:---------|
| File          | [ssh_audit_scan.py](../../toolsaf/adapters/ssh_audit_scan.py) |
| Base class    | [EndpointTool](#endpointtool) |
| Tool output   | `.json` format ssh-audit results |
| Verdict `Pass`| **FIXME** |

---
### TestSSLScan
| Property   | Details  |
|:----------:|:---------|
| File          | [testsslsh_scan.py](../../toolsaf/adapters/testsslsh_scan.py) |
| Base class    | [EndpointTool](#endpointtool) |
| Tool output   | `.json` format testssl results |
| Verdict `Pass`| **FIXME** |

---
### TSharkReader
| Property   | Details  |
|:----------:|:---------|
| File          | [tsrahk_reader.py](../../toolsaf/adapters/tshark_reader.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | `.json` format TShark BLE capture results |
| Verdict `Pass`| **FIXME** |

---
### VulnerabilityReader
| Property   | Details  |
|:----------:|:---------|
| File          | [vulnerability_reader.py](../../toolsaf/adapters/vulnerability_reader.py) |
| Base class    | [NodeComponentTool](#nodecomponenttool) |
| Tool output   | `.csv` format BlackDuck binary analysis results |
| Verdict `Pass`| **FIXME** |

---
### WebChecker
| Property   | Details  |
|:----------:|:---------|
| File          | [web_checker.py](../../toolsaf/adapters/web_checker.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | `.http` files created with `curl` |
| Verdict `Pass`| If status code in tool output is 200 and all user provided keywords included in the file |
| Other | Assigns result to system's `OnlineResources`. |

---
### ZEDReader
| Property   | Details  |
|:----------:|:---------|
| File          | [zed_reader.py](../../toolsaf/adapters/zed_reader.py) |
| Base class    | [SystemWideTool](#systemwidetool) |
| Tool output   | `.json` format ZED Attack Proxy results |
| Verdict `Pass`| **FIXME** |


## TODO
- SetupCSVReader
- ToolDepiction
- ToolFinderImplementation
- BatchImporter