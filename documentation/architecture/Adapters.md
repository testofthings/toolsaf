# Tool Adapters
This document provides information the contents of the [adapters](../../tdsaf/adapters/) directory.

## Adapter Base Classes

### ToolAdapter
File: [tools.py](../tdsaf/adapters/tools.py).

Parent of all the other tool base classes.

Notable variabels
| Variable | Description |
|----------|-------------|
| `data_file_suffix` | File type accepted by the tool |
| `system`           | IoTSystem |
| `send_events`      | Should events be logged to database |
| `load_baseline`    | **FIXME** |

### SystemWideTool
File: [tools.py](../tdsaf/adapters/tools.py).

The data processed by SystemWideTools include all the addresses/info necessary for output analysis, e.g. IP addresses, DNS names and ports. The output of a SystemWideTool is applied to the `system` as indicated by the provided tool output.

### EndpointTool
File: [tools.py](../tdsaf/adapters/tools.py).

EndpointTool applies tool output to specific endpoints. Endpoints are specified in tool outputs' file names. For example, a file called Mobile_App.xml would apply produced results to the system's endpoint named Mobile_App.

As such, tool output must be named AnyAddress + `data_file_suffix`. AnyAddress can an address tag from `00meta.json`, and IP address or DNS name.

### NetworkNodeTool
File: [tools.py](../tdsaf/adapters/tools.py).

Tool output applied to network nodes.

**FIXME**

### NodeComponentTool
File: [tools.py](../tdsaf/adapters/tools.py).

NodeComponentTool applies tool output to node components. Sample data files need to be named after components. For example, if we want to apply tool output to Mobile_App's SW component, the file name must be Mobile_App_SW + `data_file_suffix`



## Tool Adapters

### SimpleFlowTool
File: [tools.py](../tdsaf/adapters/tools.py).

**FIXME**



## TODO

**FIXME** SetupCSVReader