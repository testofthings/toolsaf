# Serialization

[Table of contents](README.md)

Toolsaf entities and some other objects are _serialized_ to and from JSON by custom serializer code.
Propietary custom serialization is used to allow full control of the JSON to match planned _Security statement JSON standard_, without sacrificing Python code readability and usability.

Serializer code is located to [serializer.py](../../toolsaf/common/serializer/serializer.py):

  - class `Serializer` which is base class for serializer classes.
    A serializer can write and/or read instances of a specified class.

  - class `SerializerContext` maintains mapping between serialized objects and their _ids_.

  - class `SerializerStream` writes and reads objects with help of serializer and context.

  - class `SerializerConfiguration` stores configuration per serializer.
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
json = stream.write(obj)
```

When reading, serializer is called repeatedly until everything is read.

```python
ser = AClassSerializer(obj)
stream = SerializerStream(ser)
for obj in stream.read():
    # New instance in 'obj'
```



