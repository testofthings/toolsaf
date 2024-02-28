# Short DSL intro

The framework uses _Domain Specific Language_ (DSL) to describe the system model.
The DSL is based on Python 3 programming language.
The following assumes basic understanding of the Python language.

## DSL essentials

Consider the following very simple model called "Basic a".
The model is in file `samples/basic-a/system.py`.

```python
from tcsfw.main import Builder, TLS

system = Builder.new("Basic A")
device = system.device()
backend = system.backend().serve()
app = system.mobile()

device >> backend / TLS
app >> backend / TLS
```

The model building start with call to `Builder.new`, which takes the name of the system as argument, and returns to system object.
The system comprises IoT _device_, _backend_ service, and a mobile _application_, called together network _nodes_. 
The device and the application connect to the backend using TLS-protected _connections_.

## Graphical view

A visual representation of a model requires placing the network nodes into canvas.
The positions are controlled using DSL, like below.

```python
system.visualize().place(
    "D   A",
    "  B  ",
) .where({
    "D": device,
    "B": backend,
    "A": app
})
```

The letters "A", "B", and "C" stand for the application, backend, and device.
Thei positions are determined in the `place` method.

## DSL reference

The interface code for the DSL is in Python module `tcsfw.main`.
DSLs can use definitions from `tcsfw.basics`, as well.
The source code in these files provides for the authorative reference code.

