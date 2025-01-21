# Services and protocols

[Table of contents](README.md)

Services are the endpoints for connections. A service can be specified explicitly like this
```python
backend_1 = system.backend().serve(HTTP, TLS)
```
Services are also created implicitly when they are referenced as connection endpoints:
```python
device >> backend_2 / TLS
```
Service definition states the served protocol.
Toolsaf supports many different protocols, see the list below.

## Choosing the right protocol

Protocols are layered on top of each other, e.g. consider protocol stack
`IP`, `TCP`, `TLS`, and `HTTP`.
These all can be used in Toolsaf services.
This opens up the question that which protocol one should use in the security statement.
The answer is that you should use the highest level supported protocol which data is visible for inspection and which is most relevant for security assessment.
For example, prefer `TLS` over `HTTP` even when the encrypted content if HTTP, as we cannot inspect the
encrypted traffic but we can verify the security of the TLS handshake, at least partially. 

An unsupported protocol can be added to the security statement like this:
```python
device >> gateway / Proprietary("connection-protocol", port=1234)
```

The port can be omitted, if there is no port concept in the proprietary protocol.
Toolsaf cannot verify such protocol. 
The goal of the Toolsaf team is to add more protocols so that the assessment coverage can be enhanced.

## Broadcast protocol

FIXME: left-shift operator etc.

The left shift operator indicates a connection from B to A, so `mobile << backend_1` means that the backend service initiates communication with the mobile application.

## List of protocols

FIXME: List the protocols available for services.