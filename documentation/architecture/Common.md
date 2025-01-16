# Common
This document provides information the contents of the [common](../../toolsaf/common/) directory.

## Addresses and Protocols
File: [address.py](../../toolsaf/common/address.py)

### Protocol
Protocol enum

### FIXME

## Android
File: [android.py](../../toolsaf/common/android.py)

Includes defintions for the Android mobile application permission categories. These can be used in security statements.

## Basics
File: [basics.py](../../toolsaf/common/basics.py)

Includes enumerator classes for the types of:
- Hosts
- Connections
- External activity levels
- Entity statuses

## Claim
File: [claim.py](../../toolsaf/common/basics.py)

**FIXME**

## Entity
File: [entity.py](../../toolsaf/common/basics.py)

**FIXME**

## Properties
File: [property.py](../../toolsaf/common/property.py)

Various property related classes.

### PropertyKey

Acts as a dict key for entities' property dicts. Example of PropertyKey creation:
```python
key = PropertyKey("component", name)
```
Typically used along with _PropertyEvents_ and the _Event interface's_ `property_update()` to set properties for various entities.

### PropertyVerdictValue

Where PropertyKey is the key in a property dictionary, PropertyVerdictValue is the key's value pair. Includes a [_Verdict_](#verdict) and an optional explanation `str`.

### PropertySetValue

**FIXME**

### Properties
A class containing built-in property keys. Used by [tool adapters](Adapters.md) when creating _PropertyEvents_. Example:
```python
ev = PropertyEvent(evidence, software, Properties.COMPONENTS.value_set(properties))
interface.property_update(ev)
```

## Release Info
File: [release_info.py](../../toolsaf/common/release_info.py)

**FIXME**

## Traffic
File: [traffic.py](../../toolsaf/common/traffic.py)

**FIXME**

## Verdicts and Related Classes
File: [verdict.py](../../toolsaf/common/verdict.py)

### Verdict
This class represents the verdicts for various entities, connections, properties, etc. set by [tool adapters](Adapters.md) based on tool output analysis results.

A verdict can be either:
- `INCON` (Inconclusive)
- `FAIL`
- `PASS`
- `IGNORE`

### Verdictable
Base class for object that have verdicts.

