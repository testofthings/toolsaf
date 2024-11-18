# Architecture

## NetworkNode
- Should have no more than 1 software component

## ToolAdapter
### EndpointTool
- file name should be AnyAddress + .file extension
  - AnyAddress can be addresses tag (00meta.json), IP address or DNS name
  - e.g. `Mobile_App.xml`
- If node is not of correct HostType raises ConfigurationException
- Node should have exctly one software component

## Exceptions
### ConfigurationException
-Configuration was incorrect
