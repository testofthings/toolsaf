## Creating Security Statements
This file explains how to structure your security statement project and how to fill in the statement using our Python DSL. Furthermore, the statements that can be made with the DSL are explained here.

### Project Structure
Security statements should be placed into their own directories, and they should be considered as their own Python projects. These directories can be their own Git repositiories. Pictured below, is the expected structure of a security statement project.
```bash
statement-product
├── .venv
└── product
    ├── __init__.py
    └── statement.py
```
Here _statement-product_ is a repository cloned from GitHub. Inside this repository we have a folder, named after the product, inside of which the actual statement file _(statement.py)_ is placed. _.venv_ is the Python virtual environment created for this project.

It should be noted that the security statements must not be placed inside the TDSAF direcotry.

### Statement Contents
A security statement is structured as follows:
```python3
"""Security statement"""

from tdsaf.main import Builder, TLS. NTP, ...

system = Builder.new("<Product name>")

# Define networks
TODO!!!!

# Define external services
any_host = system.any("Services")

# Define devives
device = system.device("<Device name>")

# Define any mobile apps
mobile = system.mobile("<Mobile app name>")

# Define relevant backend services
backend_1 = system.backend("<Service name>").serve(TLS(auth=True)).dns("<Service's DNS address>")
backend_2 = system.backend("<Service name>").serve(NTP).dns("<Service's DNS address>")
#...
backend_n = system.backend("<Service name>").serve(NTP(port=124)).dns("<Service's DNS address>")

# Define connections and protocols from the device
device >> backend_1 / TLS(auth=True)
device >> backend_2 / NTP

# Define connections and protocols from mobile apps
mobile >> backend_1 / TLS(auth=True)

```

### TODO
- Example from Deltaco **here**


### Understanding the DSL
Since the DSL is created with Python, creating security statements with it is like creating Python scripts.

Taking into consideration the example given at the start of the _**Statement Contents**_ section, security statement building starts with a call to `Builder.new`. This call takes the system's name as an argument and returns a _system_ object. It represents the whole IoT system, from the _devices_, and _backend_ services to the _mobile_ apps and networks.

When the _system_ object has been created you can start defining the different parts of the system, or nodes, using the object. These parts can include any of the following:
* Devices (`system.device`): IoT devices
* Mobile (`system.mobile`): Mobile applications
* Browser (`system.browser`): Browser application
* Backend (`system.backend`): Backend services
* Network (`system.network`): System networks
* Any (`system.any`): Conseptual node for services provided by the environment, e.g. a network router

Each node must be given a name. It is good practice to name them based on what they actually represent. For example, if the system includes a device that is a smart plug, it should be added to the system like this:
```python3
smart_plug = system.device("Smart Plug")
```

Nodes representing _backend_ services have an additonal requirement. When they are defined, the top level protocols they serve should be defined. Also their DNS name should be provided. Here's an example:
```python3
code_repository = system.backend("Code Repository").serve(HTTP, TLS(auth=True)).dns("github.com")
```
The above code creates a system backend with the name "Code Repository" that serves HTTP and authenticated TLS. Its DNS name is _github.com_.
It should be noted that adding, e.g., `TCP` to the `serve` call is only done if no higher level protocol is used there.

Connections between system components are added to the statement using the right shift operator `>>`. So, for example, `mobile >> backend_1` means that the mobile application communicates with backend service 1. This statement is immediately followed by the top level protocols used during communication. So, if the mobile application sends requests using `NTP` and `TLS` to the backend, the statement becomes:
```python3
mobile >> backend_1 / NTP / TLS
```

Connection defitions can also be shortened as follows:
```python3
backend_conn = backend / NTP / TLS

devuce >> backend_conn
mobile >> backend_conn
```

### TODO
- In the future maybe add info on **Graphical View**
