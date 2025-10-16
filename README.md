# Toolsaf

[Table of contents](documentation/README.md)

Welcome to the early version of **Toolsaf**, a tool-driven security assessment framework.
Toolsaf is for security assessment of _Internet of Things_ (IoT) and other systems using different security tools.
Security assessment process using Toolsaf has two main phases:

  1. Creation of a _security statement_ which describes security-related features of an IoT product or system.
  2. Verification of the security statement with security tools, thus confirming the security posture of the product or system.

Some of the applications of this approach could be:

  1. Security testing and regression testing of IoT systems.
  2. Communicating system security properites in a machine-readable and verifiable format.
  3. Documenting results of a system's reverse-engineering.

Toolsaf is an open-source project driven by [Test of Things](https://testofthings.com).
It was originally created as part of Rauli Kaksonen's doctoral thesis "[Transparent and tool-driven security assessment for sustainable IoT cybersecurity](https://urn.fi/URN:NBN:fi:oulu-202406264941)" under the name of 'tcsfw'.
The thesis introduces _Tool-driven security assessment_ (TDSA) to enhance the cybersecurity of
IoT products and systems.

## How Toolsaf and TDSA work?

The basic idea of TDSA is to first describe the IoT system or product with
the security statement, then use tools to verify that the security statement is accurate, and finally use
the statement for different purposes.
A security statement provides a machine-readable description of the system's security,
which allows automated verification.

At the moment, security statements are created by Toolsaf using a dedicated Python-based _Domain-Specific Language_ (DSL).
(JSON-based format is under development).
Security statement verification is done by running any of the [supported tools](documentation/Tools.md) and saving their output. Toolsaf uses the tools' output to verify that the security statement is accurate.
Some tools perform their own security checks, which can be incorporated into the security statement verdict.

## Getting Started with Toolsaf

The following shows how to start using Toolsaf.
For this, you need to perform two tasks:

  1.  Install the Toolsaf Python module.
  2.  Initialize a new or copy an existing security statement.

You need a recent [Python](https://www.python.org/) interpreter, such as 3.10 or newer.
Most Linux distributions should already come with a suitable one, the command
name might be `python3` to separate from older Python interpreters.

Create virtual environment to install Toolsaf and run it. Then install from PyPI with 'pip'.

```shell
python3 -m venv .venv
source .venv/bin/activate   # Activate the virtual environment
pip install Toolsaf
```
Now that Toolsaf is installed, you have to create a directory for your first security statement.
The commands below produce the [expected project structure](documentation/CreatingSecurityStatements.md#project-structure) for your statement.

```shell
mkdir statement-device
cd statement-device
mkdir product
touch product/statement.py  # This is the 'security statement'!
```

Alternatively, you may copy an existing security statement.
In that case you must also create and activate the virtual environment and install the Toolsaf module.

If you want to visualize your security statements you also need to install [Graphviz](https://graphviz.org/download/).

In the above, we used _venv_ virtual environments, but as security statements are essentially
Python-code, any other environment should work fine.

## Working with Security Statements

To recap, a security statement is Python DSL code in its own directory, which uses the Toolsaf Python module.
There are two basic approaches to create a security statement:

  1. Write the security statement code first, then run tools and verify it.
  2. Run tools to collect information first, then write security statement to match the findings.

If you’re the device manufacturer you will likely use the former approach, as you (hopefully)
know your product's attack surface and other properties.
If you are a security researcher who is reverse-engineering or pen-testing a product,
you have to use the latter approach.

The following documents describe security statements creation and verification:

  - [Creating Security Statements](documentation/CreatingSecurityStatements.md)
  - [Verifying Security Statements](documentation/VerifyingSecurityStatements.md)

## Command Line Options

Toolsaf is a command-line tool, and its command-line options are listed [here](documentation/CommandLineOptions.md).

## Sample Security Statements
Minimal security statement examples are available in the `samples` directory. They can be executed like this:
```shell
python samples/device-backend/statement.py
```
The command outputs basic information about the security statement.

Security statements for **real devices** are available in their own repositories:
- [Ruuvi Gateway & Tags](https://github.com/testofthings/statement-ruuvi/)
- [Deltaco Smart Outdoor Plug](https://github.com/testofthings/statement-deltaco-smart-outdoor-plug)
- [IPC360](https://github.com/testofthings/statement-IPC360)

## Contact

Contact Toolsaf team by mail <code>&#116;&#111;&#111;&#108;&#115;&#97;&#102;&#32;&#97;&#116;&#32;&#116;&#101;&#115;&#116;&#111;&#102;&#116;&#104;&#105;&#110;&#103;&#115;&#46;&#99;&#111;&#109;</code>

## License and Contributions

The project is published with [MIT license](LICENSE).

We are happy to accept contributions to Toolsaf, please see the [instructions](documentation/Contributing.md).
