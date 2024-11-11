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
* Any (`system.any`): Conseptual node for services provided by the environment, e.g. a network router

Each node must be assigned a name. It’s best to name them according to what they represent. For instance, if the system includes a smart plug, it should be added to the system like this:
```python3
smart_plug = system.device("Smart Plug")
```

Nodes representing _backend_ services have an additional requirement. When defining them, you must specify the top-level protocols they serve and provide their DNS name. Here’s an example:"
```python3
code_repository = system.backend("Code Repository").serve(HTTP, TLS(auth=True)).dns("github.com")
```
The code above creates a system backend called 'Code Repository' that supports HTTP and authenticated TLS, with a DNS name of _github.com_. Note that adding a protocol like `TCP` to the `serve` call is only necessary if no higher-level protocol is used.

Connections between system components are defined using the right shift operator `>>`. For example, `mobile >> backend_1` indicates that the mobile application communicates with backend service 1. This statement is then immediately followed by the top-level protocols used during communication. If the mobile application uses `NTP` and `TLS` to send requests to the backend, the statement becomes:
```python3
mobile >> backend_1 / NTP / TLS
```

Connection definitions can also be shortened as follows:
```python3
backend_conn = backend / NTP / TLS

devuce >> backend_conn
mobile >> backend_conn
```

### TODO
- In the future maybe add info on **Graphical View**
