# Serialization

[Table of contents](README.md)

Toolsaf entities and events are _serialized_ to and from JSON using custom code for serialization and Pydantic for deserialization. The approach was chosen for following reasons:

- Custom serialization methods give full control over the JSON output to match the planned _Security statement JSON standard_, without sacrificing Python code readability.
- DTOs (Data Transfer Objects) make the expected shape of each incoming JSON record explicit.
- A `type` discriminator field in every record provides Pydantic an easy way to select the correct DTO.

Serializer code lives in `toolsaf/core/serializer/`:
- `model_serializer.py` — `SystemSerializer` serializes and deserializes the IoT system
- `event_serializer.py` — `EventSerializer` serializes and deserializes evidence sources and the events produced by security tools.

## How it works
Both serializers expose the same two methods.
Call `serialize` to turn a model object into a list of flat JSON dicts.
Call `deserialize` to turn one JSON dict back into a model object.

```python
# Serialize
serializer = SystemSerializer()
records = serializer.serialize(system)  # returns a list of dicts

# Deserialize
serializer = SystemSerializer()
for record in records:
    serializer.deserialize(record)
```

The JSON output is a flat list of records rather than deeply nested structures.
This makes it straightforward to store in a relational database or stream over a websocket.

The two directions use different approaches under the hood.
- **Serialization** is handled by hand-written private methods on each serializer class, one per object type.
- **Deserialization** is handled by Pydantic DTOs, which validate the incoming data and reconstruct the model objects.

## SystemSerializer
### Writing
`SystemSerializer` goes through the object graph starting from whatever you pass in and queues children as it goes, so passing in the `IoTSystem` produces the serialized version of the whole security statement.

```python
serializer = SystemSerializer()
records = serializer.serialize(system)
# records[0] is the system, records[1] is the first host, etc.
```

Internally, `serializer_map` maps objects to private methods such as `_serialize_host` or `_serialize_service`. These methods build the dict.

Each record has a `type` field that identifies what it represents. Objects reference their parent by `system_address` which is a human-readable path, such as `"Device_1/tcp:80"`.

```json
{"type": "system", "system_address": "", "name": "My System", ...}
{"type": "host",   "system_address": "Device_1", "parent": "", "name": "Device 1", ...}
{"type": "service","system_address": "Device_1/tcp:80", "parent": "Device_1", ...}
```

### Reading
When deserializing, Pydantic is first used to validate given data. `SystemSerializer` creates deserialized objects by calling the DTOs' `to_model` methods. Deserialized objects are linked to their parents based on system addresses.

```python
serializer = SystemSerializer()
for record in records:
    obj = serializer.deserialize(record)  # returns the Python model object
```

## EventSerializer
### Writing
`EventSerializer` handles evidence sources and the events linked to those sources. Every event carries a reference to the `EvidenceSource` it came from. To avoid repeating the full source in every record, the serializer tracks which sources it has already serialized and only includes the source record the first time it is seen.

```python
serializer = EventSerializer(system)
records = serializer.serialize(ethernet_flow)
# records[0] is the EvidenceSource (first time only)
# records[-1] is the event itself
```

A `serializer_map` maps events and sources to a private method such as `_serialize_ethernet_flow` or `_serialize_ip_flow`, which builds the dicts.

Subsequent events from the same source just get a `source_id` reference:

```json
{"type": "source", "id": "id1", "name": "pcap-tool", "base_ref": "capture.json", ...}
{"type": "ethernet-flow", "source_id": "id1", "source": "00:11:22:33:44:55|hw", ...}
{"type": "ip-flow",       "source_id": "id1", "source": ["00:11:22:33:44:55|hw", "1.2.3.4", 443], ...}
```

### Reading
Call `deserialize` once per record. The serializer accumulates sources in its internal `source_map` so that reconstructed events can be linked to their EvidenceSources.

```python
serializer = EventSerializer(system)
for record in records:
    obj = serializer.deserialize(record)  # EvidenceSource or an event
```

## DTOs
All serialized records have a corresponding Pydantic model called a DTO. Pydantic validates the raw dict against the DTO, which catches missing fields and type mismatches early. Each DTO then knows how to turn itself into the real model object via their `to_model` method.

For example, `EthernetFlowDTO` looks roughly like this:

```python
class EthernetFlowDTO(FlowDTO):
    type: Literal["ethernet-flow"] = "ethernet-flow"
    source: str
    target: str
    payload: int

    def to_model(self, source_map, system) -> EthernetFlow:
        flow = EthernetFlow(
            self.get_evidence(source_map),
            source=HWAddress.new(...),
            target=HWAddress.new(...),
            payload=self.payload
        )
        self.populate(flow)  # fills in protocol, timestamp, properties
        return flow
```

All event DTOs inherit from `BaseEventDTO` (which has `source_id` and `tail_ref`), and flow DTOs additionally inherit from `FlowDTO` (which adds `protocol`, `timestamp`, and `properties`).

Model DTOs follow a similar hierarchy: `NetworkNodeDTO` → `AddressableDTO` → `HostDTO` / `ServiceDTO`, and so on.

## JSON Format Details
A few conventions apply across all records:
- Field names use `snake_case`.
- Timestamps are ISO 8601 strings.
- Properties are serialized as a dict keyed by property name, with the value nested inside:
```json
"properties": {
    "verdict:key": {"verdict": "Pass", "exp": "explanation text"}
}
```
