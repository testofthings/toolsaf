# Architecture

The following image shows the overall Toolsaf software architecture.

![Architecture Diagram](../img/architecture.png)

Main components in the architecture diagram are the following:

 * **Builder DSL**: System builder configured by the DSL.
   Main classes: `Builder` and `BuilderBackend`.

 * **IoT system**: The class hierarchy of the modeled IoT system.
   Main class: `IoTSystem`.
   The most essential classes for the model are the following:

   * **Host**: Represents all hosts; its children are services.

   * **Service**: Represents a service within a host.

   * **NodeComponent**: Base class for internal host components, such as _software_ components.

   * **IoTSystem**: Represents the IoT system, with its children being the hosts.

 * **Event interface**: A pipeline of classes that implement the
   `EventInterface` class. These consume _Events_ (see [`common`](Common.md) sub-module), process them, and
   finally update the system model.

   * **Registry**: Provides short-term event storage in a database.
     Allows users to reload stored events.
     Main class: `Registry`.

   * **Event logger**: Stores events and the properties they change
     so that the reason for property changes can be retrieved later.
     Main class: `EventLogger`.

   * **Inspector**: Inspects events and updates the IoT system model
     accordingly. This requires matching addresses and connections to
     various system entities.
     Main classes: `Inspector` and `Matcher`.

 * **Batch importer**: Reads *batch files* of tool results and uses
   various [**Tool adapters**](Adapters.md) to convert input into events.
   Main classes: `BatchImporter` and `ToolAdapter`.

 * **Reporter**: Reads the IoT system and its properties to output
   textual or graphical results with verdicts.

 * **Uploader**: Uploads the IoT system and events into cloud storage,
   if instructed from command line.

## Module documentation

| Sub-module                              |  Description |
|-----------------------------------------|--------------|
| [`toolsaf`](Main.md)                    | Main classes and Toolsaf entry point |
| [`toolsaf/common`](Common.md)           | Common utilities used by all sub-modules |
| [`toolsaf/common/serializer`](Serialization.md) | Serializing object to JSON and back |
| [`toolsaf/core`](Core.md)               | Core classes of the Toolsaf architecture |
| [`toolsaf/adapters`](Adapters.md)       | Tool adapters |
