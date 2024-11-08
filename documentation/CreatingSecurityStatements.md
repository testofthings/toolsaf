## Creating Security Statements
TODO

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
A security statement should be structured as follows:
```python3
from tdsaf.main import Builder, TLS. NTP, ...

system = Builder.new("<Product name>")

# Define networks
TODO!!!!

# Define external services, e.g., gateway
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
device >> backend_2 / NTP

# Define connections and protocols from mobile apps
mobile >> backend_1 / TLS(auth=True)
```

### Understanding the DSL
TODO

**Top level** protocols to serve