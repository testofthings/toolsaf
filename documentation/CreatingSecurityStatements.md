# Creating Security Statements
This document provides guidance on structuring your security statement project and details how you can fill in the statement using our Python DSL. Additionally, it outlines the various types of statements that can be created with the DSL.

## Project Structure
Security statements for each product should be placed in their own directory in a Python project. Each project is recommended to be version controlled as a Git repository.
One respository can contain one or several products, each in own directory.
Below is the expected structure for a security statement project:
```
repository-name
├── .venv
└── product-name
    ├── __init__.py
    └── statement.py
```
_repository-name_ refers to a repository cloned from GitHub. Inside this repository is a folder or folders named after products, which contain the actual statement file _(statement.py)_. The .venv folder is the Python virtual environment for the project, into which TDSAF is installed.

Note that security statements should not be placed inside the TDSAF directory.

## Statement Contents
A security statement is structured as follows:
```python
"""Security statement"""

from tdsaf.main import Builder, TLS. NTP, ...
from tdsaf.common.android import STORAGE, RECORDING

system = Builder.new("<Product name>")

# Define external services
any_host = system.any("Services")

# Define devices
device = system.device("<Device name>")

# Define open ports on the devices
open_port_1 = device / SSH

# Define any mobile apps
mobile = system.mobile("<Mobile app name>")
# Define mobile app permissions
mobile.set_permissions(STORAGE, RECORDING)

# Define relevant backend services
backend_1 = system.backend("<Service name>").serve(TLS).dns("<Service's DNS name>")
backend_2 = system.backend("<Service name>").serve(NTP).dns("<Service's DNS name>")
backend_3 = system.backend("<Service name>").serve(TLS(port=1443)).dns("<Service's DNS name>")
#...
backend_n = system.backend("<Service name>").serve(NTP).dns("<Service's DNS name>")

# Define connections from the environment
any_host >> device / ARP

# Define connections and protocols from the device
device >> backend_1 / TLS
device >> backend_2 / NTP

# Define connections and protocols from mobile apps
mobile >> backend_1 / TLS

if __name__ == '__main__':
    system.run()

```
The above example utilized the `tdsaf.main` Python module's interface code for our DSL. However, definitions from `tdsaf.common.basics` can also be used when creating security statements.

### Real World Example
Now that we know the structure of a security statement, let's look at a real world example. Here is the security statement we created for the _Deltaco Smart Outdoor Plug_:
```python
""" Security statement """
from tdsaf.main import Builder, TLS, DNS, UDP, ARP, EAPOL, ICMP, TCP
from tdsaf.common.android import LOCATION, BLUETOOTH, ADMINISTRATIVE, NETWORK, RECORDING, STORAGE, UNCATEGORIZED

# Start modeling the IoT system
system = Builder.new("Deltaco Smart Outdoor Plug")

# Defining services by the environment (WiFi-hotspot)
any_host = system.any("Services")

# Defining the device
smart_plug = system.device("Smart Plug")

# Define open ports on the device
smart_plub_tcp_port = smart_plug / TCP(port=6668)
smart_plug_udp_port = smart_plug / UDP(port=63144)

# Defining the mobile app
mobile_app = system.mobile("Smart Home App")

# Defining mobile app permissions
mobile_app.set_permissions(
    LOCATION, BLUETOOTH, ADMINISTRATIVE, NETWORK, RECORDING, STORAGE, UNCATEGORIZED
)

# Defining broadcasts
udp_broadcast_1 = system.broadcast(UDP(port=6667))
udp_broadcast_2 = system.broadcast(UDP(port=7000))
udp_broadcast_3 = system.broadcast(UDP(port=30011))
udp_broadcast_4 = system.broadcast(UDP(port=30012))

# Defining relevant backend services
tuya_1 = system.backend("Tuya Smart 1").serve(TLS).dns("a1.tuyaeu.com")
tuya_2 = system.backend("Tuya Smart 2").serve(TLS(port=8883)).dns("m1.tuyaeu.com")
tuya_3 = system.backend("Tuya Smart 3").serve(TLS).dns("a3.tuyaeu.com")
tuya_4 = system.backend("Tuya Smart 4").serve(TLS(port=8886)).dns("m2.tuyaeu.com")
tuya_images = system.backend("Tuya Images").serve().dns("images.tuyaeu.com")
aws = system.backend("AWS").serve(TLS).dns("euimagesd2h2yqnfpu4gl5.cdn5th.com")
aws_iot_dns = system.backend("AWS IoT DNS").serve(TLS).dns("h3.iot-dns.com")
tencent = system.backend("Tencent Cloud Computing").serve(TCP(port=443)).dns("tencent.com")

# Defining connections by the environment
any_host >> smart_plug / ARP / EAPOL / ICMP
any_host >> mobile_app / ARP

# Defining connections from the device
smart_plug >> any_host / DNS / ICMP
smart_plug >> udp_broadcast_1
smart_plug >> mobile_app / ARP
smart_plug >> tencent / TCP(port=443)
smart_plug >> tuya_3 / TLS
smart_plug >> tuya_4 / TLS(port=8886)
smart_plug >> aws_iot_dns / TLS

# Defining connections from the mobile application
mobile_app >> udp_broadcast_2
mobile_app >> udp_broadcast_3
mobile_app >> udp_broadcast_4
mobile_app >> any_host / DNS / ARP
mobile_app >> smart_plub_tcp_port
mobile_app >> tuya_1 / TLS
mobile_app >> tuya_2 / TLS(port=8883)
mobile_app >> tuya_images / TLS
mobile_app >> aws / TLS

if __name__ == '__main__':
    system.run()

```
As we do not know the inner working of the device, this statement was made based on the network traffic data.

## Understanding the DSL
Since our DSL is built with Python, creating security statements is similar to writing Python scripts.

As shown in the example at the beginning of the _**Statement Contents**_ section, building a security statement starts with a call to `Builder.new`. This call takes the system's name as an argument and returns a _system_ object, which represents the entire IoT system—from the _devices_, and _backend_ services to the _mobile apps_ and _networks_.

Once the _system_ object is created, you can begin defining the various components, or nodes, of the system using this object. These components may include any of the following:
* Devices (`system.device`): IoT devices
* Mobile (`system.mobile`): Mobile applications
* Browser (`system.browser`): Browser application
* Backend (`system.backend`): Backend services
* Network (`system.network`): System networks
* Any (`system.any`): Conceptual node for services provided by the environment, e.g. a network router
* Broadcast (`system.broadcast`): **FIXME**

Each node can be assigned a name. It's best to name them according to what they represent. For instance, if the system includes a smart plug, it should be added to the system like this:
```python
smart_plug = system.device("Smart Plug")
```

Nodes representing _backend_ services have an additional requirement. When defining them, you must specify the top-level protocols they serve and provide their DNS name. Here's an example:"
```python
code_repository = system.backend("Code Repository").serve(HTTP, TLS).dns("github.com")
```
The code above creates a system backend called 'Code Repository' that supports HTTP and TLS, with a DNS name of _github.com_. Note that adding a protocol like `TCP` to the `serve` call is only necessary if no higher-level protocol is used.

Connections between system components are defined using the right and left shift operators `>>` `<<`. The right shift operator indicates a connection from A to B. For example, the statement `mobile >> backend_1` means that the mobile application initiates a connection with backend service 1. Conversely, the left shift operator indicates a connection from B to A, so `mobile << backend_1` means that the backend service initiates communication with the mobile application.

Statements using the shift operators are typically followed by `/` and the top-level protocols used in the connection. For instance, if the mobile application connects to the backend using `TLS`, the statement becomes:
```python
mobile >> backend_1 / TLS
```
Additional protocols can be added to the statement by appending the statement with `/ <protocol>`.
```python
mobile >> backend_1 / TLS / SSH
```

Connection definitions can also be shortened as follows:
```python
backend_conn = backend / TLS / SSH

device >> backend_conn
mobile >> backend_conn
```

## Additional DSL Definitions
### Mobile Application Permissions (Android Only)
Typically mobile applications ask their users to grant them certain permissions. These permissions should be included in the security statement. You can define them with:
```python
from tdsaf.common.android import STORAGE, LOCATION, ...

mobile.set_permissions(STORAGE, LOCATION, ...)
```
However, since there are [hundreds of different permissions](https://developer.android.com/reference/android/Manifest.permission), **use the permission categories we have created** in your security statements. TDSAF handles the rest.

Our permission categories are:
- `CALLS`
- `SMS`
- `CONTACTS`
- `CALENDAR`
- `LOCATION`
- `RECORDING`
- `STORAGE`
- `NETWORK`
- `HEALTH`
- `ACCOUNT`
- `BILLING`
- `BLUETOOTH`
- `ADMINISTRATIVE`
- `UNCATEGORIZED`

An up-to-date list of categories can always be found [here](../tdsaf/common/android.py). You can check into which category a permission belongs to from [this json file](../tdsaf/adapters/data/android_permissions.json). Currently, if a permission is not in the _.json_ file, its category will be `UNCATEGORIZED`.

## When the Statement is Defined
To ensure that your statement is filled in properly, run the statement file with Python. This way you can be sure that its free of runtime errors.
```shell
python3 statement.py
```
Once the security statement is complete, it is ready for [verification](VerifyingSecurityStatements.md).

### Info on `broadcast`

FIXME

## Graphical view

**FIXME: Keep or drop?**
A visual representation of a model requires placing the network nodes into a canvas. The positions are controlled using DSL, like below.

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
Their positions are determined in the `place` method.
