# Architecture

The following image shows the overall framework software architecture.

![Architecture Diagram](img/architecture.png)

Main components in the arhitecture diagram are the following:

 * **Builder DSL**: System builder which is configured by DSL.
   Main classes `Builder` and `BuilderBackend`.

 * **IoT system**: The class hierarchy of the modeled IoT system.
   Main class `IoTSystem`.

 * **Event interface**: Pipeline of classes which implement the
   `EventInterface` class. The consume *Events*, process them, and
   finally update the system model.

   * **Registry**: Provide long-term storage of the events in DB.
     Allows to reload stored events later.
     Main class `Registry`.

    * **Event logger**: Store events and the properties they change
      so that the reason for property changes can be retrieved later.
      Mail class `EventLogger`.

    * **Inspector**: Inspect events and update the IoT system model
      accordingly. This requires matching addresses and connections into
      various system entities.
      Main classes `Inspector` and `Matcher`.

  * **Batch importer**: Read *batch files* of tool results and use
    various **Tool adapters** which convert input into events.
    Main classes `BatchImporter` and `ToolAdapter`.

  * **Reporter**: Read IoT system and its properties to output
    textual or graphical result output with verdicts.

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
