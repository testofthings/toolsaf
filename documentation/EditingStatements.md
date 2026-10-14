# Editing loaded statements

[Table of contents](README.md)

A serialized security statement can be loaded and edited with the same DSL used to create statements.
The changes can be retrieved as statement JSON records.

```python
system = Builder.load("statement.json")
device = system.device("Device 1")  # existing host, by name
device.name("Lamp")
device.set_addresses(["192.168.0.6", "lamp.example.com|name"])
system.device("Lamp") / HTTP  # new service
```

## System addresses
Each entity has a _system address_, e.g. `Device_1` for a host and `Device_1/tcp:80` for its service.
The address of a host or a component is based on its _tag_, which is set from the original name, e.g. `Device_1` for `Device 1`.
The tag does not change when the entity is renamed, thus the system address is stable.
An entity is found by its system address as follows, `None` is returned for an unknown address:
```python
entity = system.system.find_entity(Addresses.parse_system_address("Device_1/tcp:80"))
if entity is None:
    raise ValueError("No entity at Device_1/tcp:80")
```

## Renaming
`name()` changes the name of a host, service, or software, but not its system address.
A name with a dot is also added as DNS name, unless `check_dns=False` is given.
```python
device.name("Lamp")
device.name("Lamp v2.1", check_dns=False)
```

## Removing
`remove_entity()` removes a host, service, connection, or component, e.g. software.
Services and components of a removed host or service are removed, too.
Connections must be removed first, the removal fails while connections refer to the removed entities.
Ignore rule locations of the removed entities are removed.
`remove_network()` removes a network, which must not be used by any entity.
```python
for address in ["source=Device_1&target=Backend/tcp:443", "Device_1"]:
    entity = system.system.find_entity(Addresses.parse_system_address(address))
    if entity is None:
        raise ValueError(f"No entity at {address}")
    system.remove_entity(entity)
```
Events of removed entities are skipped when the statement is loaded.

## Host addresses
`set_addresses()` replaces IP, HW, and DNS addresses of a host.
The addresses are given as in the statement JSON, e.g. `"192.168.0.6"`, `"02:00:00:00:00:01|hw"`, `"lamp.example.com|name"`.
The tag is always kept, thus an empty list leaves only the tag.

## Statement changes
`serialize_statement_changes()` returns the records changed since the previous call.
A record of a removed entity only has the address, e.g. `{"address": "Device_1/tcp:80", "type": "removed"}`.
Removals are first, then the changed records.
Applying the records in order never leaves a record referring to a removed or missing one.
```python
for record in system.serialize_statement_changes():
    ...
```
