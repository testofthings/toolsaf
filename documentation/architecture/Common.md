# Common

[Architecture root](README.md)

This document provides information the contents of the [common](../../toolsaf/common/) directory.

## File [basics.py](../../toolsaf/common/basics.py)

This file holds basic enumerations.
 - `HostType` such as _device_ or _backend_.
 - `ConnectionType` such as _encrypted_ or _administrative_.
 - `ExternalActivity` levels which determine how much unexpected traffic is allowd before fail verdict.
 - Entity `Status`es, the most important ones are:
   - `EXPECTED` when the entity is defined in security statment.
   - `UNEXPECTED` when the entity was not in the security statement and created on-the-fly and usually lead to fail verdict.
   - `EXTERNAL` for entity not in security statement, but consider out-of-scope and thus ignored.

## File [address.py](../../toolsaf/common/address.py)

File defines enumeration of supported `Protocol`s and different types of addresses.

Addresses include _IP addresss_, _HW addresses_, _DNS names_ and other types.
Addresses are used for finding rigth hosts and services, e.g. for verification
from traffic capture.
Special address type is _tag_, which is generated for each expected part of the system
and thus is always available to refer them.
Tags shoud be used in _batch files_ to assign proper other addresses for hosts.

## File [entity.py](../../toolsaf/common/basics.py)

Entity is the base class for all parts of IoT system, including hosts, services, and components.

## File [property.py](../../toolsaf/common/property.py)

Each `Entity` has a map of properties. Propeties are added to a map as result of tool output by adapters, but they are also used as open attribute store for entities.
Class `PropertyKey` is the property map key type.
Utility class `Properties` holds the built-in property keys.

There are two special property value types:

  * `PropertyVerdictValue` is made up of `Verdict` and optional explanation

  * `PropertySetValue` comprises set of property keys and optional explanation. 
     A verdict for such property is evaluated by inspecting the verdict of 
     all properties in the set.


## File [release_info.py](../../toolsaf/common/release_info.py)

Somewhat experimental storage for release information of a product.

## File [traffic.py](../../toolsaf/common/traffic.py)

Classes for traffic flows and events in general.
`Event` is the base class for events carried from _tool adapters_ into the model.
Events update the model and assign verdicts, not the tool adapters directly.
Event types are the following:

  * `Flow`
    * `EthernetFlow` for ethernet frame
    * `IPFlow` for IP packet
    * `BLEAdvertisementFlow` for BLE advertisement frame
  * `ServiceScan` for network scan result for a _service_
  * `HostScan` for network scan result for a _host_

Some event types are defined elsewhere, but show here for convenience.

  * `NameEvent` for DNS name event.
  * `PropertyEvent` for direct _property_ update for given entitiy.
  * `PropertyAddress` for directly _property_ update for given address.

## File [verdict.py](../../toolsaf/common/verdict.py)

Class `Verdict` represents the verdicts for entities, connections, properties, etc.
usually set by [tool adapters](Adapters.md) based on tool output analysis results.

A verdict can be either:
- `INCON` for inconclusive, verdict cannot be resolved
- `FAIL` verdict
- `PASS` verdict
- `IGNORE` when the verdict would not be relevant and should be ignored.

Class `verdictable` is base class for object that have verdicts.

## File [android.py](../../toolsaf/common/android.py)

Includes defintions for the Android mobile application permission categories. These can be used in security statements.
