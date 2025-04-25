# Serialization

[Table of contents](README.md)

Toolsaf entities and some other objects are _serialized_ to and from JSON by custom serializer code.
Propietary custom serialization is used for following reasons:

  - Allow full control of the JSON to match planned _Security statement JSON standard_, without sacrificing Python code readability and usability.

  - Support serialization model where a stream of JSON objects is read and write rather
  than deeply nested JSON structures.
  This supports storing of data in relational DB:s and easy updates of serialized objects
  through e.g. websockets towards Web front-ends.

Serializer code is located to [serializer.py](../../toolsaf/common/serializer/serializer.py):

  - Generics class `Serializer` which is base class for serializer classes.
    A serializer can write and/or read instances of a specified class.

  - Class `SerializerContext` maintains mapping between serialized objects and their _ids_.

  - Class `SerializerStream` writes and reads objects with help of serializer and context.

  - Class `SerializerConfiguration` stores configuration per serializer.
    Each serializer has the configuration in field `config`.

Basic premise is that the serialized classes do not need to have any changes for reading or writing.
The downside is that a separate _serializer_ class (derived from `Serializer`) is required.
Separate serializer may be needed for each serialized class or single serializer may
implement the functionality for many classes.

## Basic use

An object is written the following manner:
```python
# 'obj' of class AClass is the object to write into 'json'
ser = AClassSerializer(obj)
stream = SerializerStream(ser)
for json in stream.write(obj):
    # New JSON in 'json'
```

Note that an object can produce one or more JSON blobs of data.
When reading, serializer is called repeatedly until everything is read.

```python
ser = AClassSerializer(obj)
stream = SerializerStream(ser)
for obj in stream.read():
    # New instance in 'obj'
```

A serialized object looks what you would except, `id1` is the object id, which can be
used to refer the object later in the stream.
```json
{"id": "id1", "a_string": "AAA", "a_int": 2000}
```

## Implementing serializer

Following shows a simple class and it's serializer class.

```python
class AClass:
    """Test class A for serialization"""
    def __init__(self, a_string: str, a_int: int) -> None:
        self.a_string = a_string
        self.a_int = a_int

class AClassSerializer(Serializer[AClass]):
    """Serializer for A class"""
    def __init__(self):
        super().__init__(AClass)
        self.config.map_simple_fields("a_string", "a_int")
```

As seen, the serializer must tell `Serializer` which class instances it is
serializing. Then it defines the simple fields which are 1:1 mapped into JSON fields.
This is done through field `config` of the serializer.

A serializer is free to require access to other objects which are required
for proper serialization. E.g. consider the following serializer.
```python
class NetworkNodeSerializer(Serializer):
    """Base class for serializing network nodes"""
    def __init__(self, root: 'IoTSystemSerializer') -> None:
        super().__init__(class_type)
        self.root = root
```
This serializer requires access to _root_ serializer, which is available in diffenent
methods explained below.

### Custom writer and reader

A serializer class can implement a custom writer in following manner by `+=`operator (there is also method `write_field` if this looks too scary).
```python
    def write(self, obj: AClass, stream: SerializerStream) -> None:
        stream += "custom-value", "..."
```

It is custom to assert the proper class for the writen data.
Reading is done by "subtracting" from stream with `-` , like this (method `get` works similar fashion).

```python
    def read(self, obj: Any, stream: SerializerStream) -> None:
        assert isinstanceof(obj, AClass)
        # Read from custom JSON
        custom_value = stream - "custom-value"  # get string value from JSON
```

Above code returns `None` when "custom-value" is not present. Getter `stream["custom-value"]` would throw an exception.

### Creating new instances on read

Normally, an object is created by constructor which does not take parameter.
If other constructors should be used, then serializer can implement
method `new`.

```python
    def new(self, stream: SerializerStream) -> Optional[AClass]:
        # Return new instance of the proper class
```

Returning `None` allows you to skip the object and discard the related JSON.
This is handy when an object may become obsolete and can be omitted.

### Serializing sub-objects

Consider the follwing class which holds list of objects of type `AClass`,
and its serializer class.
Note how the `write`  method explicitly serialize sub-objects, which
are pushed and read from the stream.
We must also update `AClass` serializer to add the read objects properly.

```python
class AClassSerializer(Serializer[AClass]):
    """Serializer for A class"""
    def __init__(self):
        super().__init__(AClass)
        self.config.map_simple_fields("a_string", "a_int")

    def read(self, obj: AClass, stream: SerializerStream) -> None:
        parent = stream.resolve(of_type=BClass)
        parent.sub_instances.append(obj)

class BClass:
    """Test class B for serializer"""
    def __init__(self):
        self.sub_instances: List[AClass] = []

class BClassSerializer(Serializer[BClass]):
    """Serializer for B class"""
    def __init__(self):
        super().__init__(BClass)
        self.config.map_class("a-type", AClassSerializer())

    def write(self, obj: BClass, stream: SerializerStream) -> None:
        stream.push_all(obj.sub_instances, at_object=obj)

```

The JSON stream may look like this:
```json
{"id": "id1"},
{"id": "id2", "type": "a-type", "at": "id1", "a_string": "First", "a_int": 101},
{"id": "id3", "type": "a-type", "at": "id1", "a_string": "Second", "a_int": 102},
{"id": "id4", "type": "a-type", "at": "id1", "a_string": "Third", "a_int": 103},
```

The field `type` specifies the type string given `config.map_new_class`.
The field `at` specifies which parent should _read_ the instance.
