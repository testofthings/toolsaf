# Core

[Architecture root](README.md)

This document provides information about the contents of the [core](../../toolsaf/core/) directory.

## File [`model.py`](../../toolsaf/core/model.py)

This file contains the essential IoT system building blocks:

  * `NetworkNode` is the base class for network nodes, which can be made up of child nodes and _components_. Subclasses include _hosts_, _services_, and the _IoT system_.
  * `Addressable` is a network node that has address(es).
  * `Host` is addressable, and its children are _services_.
  * `Service` is addressable.
  * `IoTSystem` is a network node representing the whole system.
  * `Connection` is a connection between addressable entities.
  * `NodeComponent` is the base class for internal components of a _network node_.
  * `ModelListener` is an interface to receive update events from the model.

## File [`services.py`](../../toolsaf/core/services.py)

This file contains implementations for some special _services_.

## File [`components.py`](../../toolsaf/core/components.py)

This file contains the implementation of network node _components_.

## File [`ignore_rules.py`](../../toolsaf/core/ignore_rules.py)

Enables the creation of _IgnoreRules_ for masking false positive security tool findings in security statements.

## File [`event_interface.py`](../../toolsaf/core/event_interface.py) and related files

The event interface is the base class for classes that receive and process _events_.
Implementations are in the following files:

  * File [`event_logger.py`](../../toolsaf/core/event_logger.py) creates logs of events to assign them to property changes.
  * File [`inspector.py`](../../toolsaf/core/inspector.py) processes events and updates the model accordingly, including the creation of unexpected nodes and services, and verdict assignment. Takes _IgnoreRules_ into account.

## Files [`entity_database.py`](../../toolsaf/core/entity_database.py)

These files implement experimental DB storage of _events_.
This code is subject to refactoring.

## File [`matcher.py`](../../toolsaf/core/matcher.py)

The matcher is a complex module for matching different _events_ to hosts, services, and connections.

## File [`result.py`](../../toolsaf/core/result.py)

This file implements the result printout of Toolsaf.

## File [`online_resources.py`](../../toolsaf/core/online_resources.py)

This class stores _online resource_ data.

## File [`uploader.py`](../../toolsaf/core/uploader.py)

This file implements sending JSON serializer security statements to our API. Requests are authenticated with an API key.
