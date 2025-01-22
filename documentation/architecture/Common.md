# Common

[Architecture root](README.md)

This document provides information about the contents of the [common](../../toolsaf/common/) directory.

## File [basics.py](../../toolsaf/common/basics.py)

This file holds basic enumerations:
 - `HostType` such as _device_ or _backend_.
 - `ConnectionType` such as _encrypted_ or _administrative_.
 - `ExternalActivity` levels which determine how much unexpected traffic is allowed before a fail verdict.
 - Entity `Status`es, the most important ones are:
   - `EXPECTED` when the entity is defined in the security statement.
   - `UNEXPECTED` when the entity was not in the security statement and was created on-the-fly, usually leading to a fail verdict.
   - `EXTERNAL` for entities not in the security statement, but considered out-of-scope and thus ignored.

## File [address.py](../../toolsaf/common/address.py)

This file defines an enumeration of supported `Protocol`s and different types of addresses.

Addresses include _IP addresses_, _HW addresses_, _DNS names_, and other types. Addresses are used for finding the right hosts and services, e.g., for verification from traffic capture. A special address type is _tag_, which is generated for each expected part of the system and is always available to refer to them. Tags should be used in _batch files_ to assign proper other addresses for hosts.

## File [entity.py](../../toolsaf/common/entity.py)

`Entity` is the base class for all parts of the IoT system, including hosts, services, and components.

## File [property.py](../../toolsaf/common/property.py)

Each `Entity` has a map of properties. Properties are added to a map as a result of tool output by adapters, but they are also used as an open attribute store for entities. The class `PropertyKey` is the property map key type. The utility class `Properties` holds the built-in property keys.

There are two special property value types:

  * `PropertyVerdictValue` is made up of `Verdict` and an optional explanation.

  * `PropertySetValue` comprises a set of property keys and an optional explanation.
     A verdict for such a property is evaluated by inspecting the verdict of
     all properties in the set.

## File [release_info.py](../../toolsaf/common/release_info.py)

This is a somewhat experimental storage for release information of a product.

## File [traffic.py](../../toolsaf/common/traffic.py)

This file contains classes for traffic flows and events in general.
`Event` is the base class for events carried from _tool adapters_ into the model. Events update the model and assign verdicts, not the tool adapters directly.

Event types are the following:

  * `Flow`
    * `EthernetFlow` for Ethernet frames
    * `IPFlow` for IP packets
    * `BLEAdvertisementFlow` for BLE advertisement frames
  * `ServiceScan` for network scan results for a _service_
  * `HostScan` for network scan results for a _host_

Some event types are defined elsewhere but are shown here for convenience:

  * `NameEvent` for DNS name events.
  * `PropertyEvent` for direct _property_ updates for a given entity.
  * `PropertyAddress` for direct _property_ updates for a given address.

## File [verdict.py](../../toolsaf/common/verdict.py)

The class `Verdict` represents the verdicts for entities, connections, properties, etc., usually set by [tool adapters](Adapters.md) based on tool output analysis results.

A verdict can be either:
- `INCON` for inconclusive, verdict cannot be resolved
- `FAIL` verdict
- `PASS` verdict
- `IGNORE` when the verdict wouldn't be relevant and should be ignored.

The class `verdictable` is the base class for objects that have verdicts.

## File [android.py](../../toolsaf/common/android.py)

This file includes definitions for the Android mobile application permission categories. These can be used in security statements.
