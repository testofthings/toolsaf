## Creating Security Statements
This document provides guidance on structuring your security statement project and details how you can fill in the statement using our Python DSL. Additionally, it outlines the various types of statements that can be created with the DSL.

### Project Structure
Security statements for each unique product should be placed in their own directory and treated as a standalone Python project. These directories can also function as individual Git repositories. Below is the expected structure for a security statement project:
```bash
statement-product-name
├── .venv
└── product-name
    ├── __init__.py
    └── statement.py
```
_statement-product-name_ refers to a repository cloned from GitHub. Inside this repository is a folder named after the product, which contains the actual statement file _(statement.py)_. The .venv folder is the Python virtual environment for the project, into which TDSAF is installed.

Note that security statements should not be placed inside the TDSAF directory.

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

# Define devices
device = system.device("<Device name>")

# Define open ports on the devices
open_port_1 = device / SSH

# Define any mobile apps
mobile = system.mobile("<Mobile app name>")

# Define relevant backend services
backend_1 = system.backend("<Service name>").serve(TLS(auth=True)).dns("<Service's DNS name>")
backend_2 = system.backend("<Service name>").serve(NTP).dns("<Service's DNS name>")
#...
backend_n = system.backend("<Service name>").serve(NTP(port=124)).dns("<Service's DNS name>")

# Define connections and protocols from the device
device >> backend_1 / TLS(auth=True)
device >> backend_2 / NTP

# Define connections and protocols from mobile apps
mobile >> backend_1 / TLS(auth=True)

```
The above example utilized the `tdsaf.main` Python module's interface code for our DSL. However, definitions from `tdsaf.common.basics` can also be used when creating security statements.


#### TODO
- Define networks in the above example
- Example from Deltaco **here**


### Understanding the DSL
Since our DSL is built with Python, creating security statements is similar to writing Python scripts.

As shown in the example at the beginning of the _**Statement Contents**_ section, building a security statement starts with a call to `Builder.new`. This call takes the system's name as an argument and returns a _system_ object, which represents the entire IoT system—from the _devices_, and _backend_ services to the _mobile apps_ and _networks_.

Once the _system_ object is created, you can begin defining the various components, or nodes, of the system using this object. These components may include any of the following:
* Devices (`system.device`): IoT devices
* Mobile (`system.mobile`): Mobile applications
* Browser (`system.browser`): Browser application
* Backend (`system.backend`): Backend services
* Network (`system.network`): System networks
* Any (`system.any`): Conceptual node for services provided by the environment, e.g. a network router
* Broadcast (`system.broadcast`): **TODO**

Each node must be assigned a name. It’s best to name them according to what they represent. For instance, if the system includes a smart plug, it should be added to the system like this:
```python3
smart_plug = system.device("Smart Plug")
```

Nodes representing _backend_ services have an additional requirement. When defining them, you must specify the top-level protocols they serve and provide their DNS name. Here’s an example:"
```python3
code_repository = system.backend("Code Repository").serve(HTTP, TLS(auth=True)).dns("github.com")
```
The code above creates a system backend called 'Code Repository' that supports HTTP and authenticated TLS, with a DNS name of _github.com_. Note that adding a protocol like `TCP` to the `serve` call is only necessary if no higher-level protocol is used.

Connections from one system component to another are defined using the right and left shift operators `>>`, `<<`. The right shift operator indicates that a connection is sent from A to B. As an example, the statement `mobile >> backend_1` means that the mobile application initiates communications by connecting to backend service 1. On the other hand, the statement `mobile << backend_1` indicates that a connection is sent from B to A. So the statement's meaning becomes that communications between the mobile application and the backend service are initiated by the backend service.

Connections between system components are defined using the right and left shift operators `>>` `<<`. The right shift operator indicates a connection from A to B. For example, the statement `mobile >> backend_1` means that the mobile application initiates a connection with backend service 1. Conversely, the left shift operator indicates a connection from B to A, so `mobile << backend_1` means that the backend service initiates communication with the mobile application.

Statements using the shift operators are typically followed by `/` and the top-level protocols used in the connection. For instance, if the mobile application connects to the backend using `TLS`, the statement becomes:
```python3
mobile >> backend_1 / TLS
```
Additional protocols can be added to the statement by appending the statement with `/ <protocol>`.
```python3
mobile >> backend_1 / TLS / SSH
```

Connection definitions can also be shortened as follows:
```python3
backend_conn = backend / TLS / SSH

device >> backend_conn
mobile >> backend_conn
```

#### TODO
- Info on `broadcast`


### TODO
- Mention claims
- In the future maybe add info on **Graphical View**
