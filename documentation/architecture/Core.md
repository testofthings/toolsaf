# Core

[Architecture root](README.md)

This document provides information the contents of the [core](../../toolsaf/core/) directory.

## File `model.py`

This file contains the essential IoT system building blocks.

  * `NetworkNode` is base class for network nodes, which can be made up of child nodes and _components_. Subclasses include _hosts_, _services_, and the _IoT system_.
  * `Addressable` a network node which have address(es).
  * `Host` is addressable and its children are _services_.
  * `Service` is addressable.
  * `IoTSystem` is network node representing the whole system.
  * `Connection` is a connection between addressable entities.
  * `NodeComponent` is base class for internal component of _network node_.
  * `ModelListener` is interface to receive update events fron the model.

## File `services.py`

This file contains implementations for some special _services_.

## File `components.py`

This file contains implementation of network node _components_.

## File `event_interface.py` and related files

Event interface is base class for clasess which receive and process _events_.
Implementations are in the following files:

  * File `registry.py` Implement entity identities and experimental DB storage of events.
  * File `event_logger.py` Creates log of events to assign tham into property changes.
  * File `inspector.py` Processes evens and updates the model accordingly, including creation of unexpected node and services and verdict assignment.

## Files `entity_database.py` and `sql_database.py`

These files implement experimental DB storage of _events_.
This code is subject to refactoring.

## File `matcher.py`

Matcher is a complex module for matching different _events_ into host, services, and connections.

## Files `entity_selector.py` and `selector.py`

These files implements _selectors_ which allows selecting some model entities, e.g. "select all hosts which are not expected".
The class `Select` contains factory methods for all selectors.

The class `Finder` implements reading and writing of JSON data to pinpoint individual entities.
NOTE: This class should be retired in favor of _addresses_,
once they can be used to identify any entity.

## File `result.py`

The file implements the result printout of Toolsaf.

## File `main_tools.py`

This file provides some core classes for Toolsaf DSL interface and implementation.

## File `online_resources.py`

Class to store _online resource_ data.
