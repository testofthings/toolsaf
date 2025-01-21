# Toolsaf

[Table of contents](documentation/README.md)

Welcome to early version of **Toolsaf**, a tool-driven security assesment framework.
Toolsaf is intended for security assessment of _Internet of Things_ (IoT) and other systems by help of common security tools.
The process of using Toolsaf for security assessment has tool main phases:

  1. Creation of a _security statement_ which describes security-related features of an IoT product or system.
  1. Verification of the security statement by security tools.

Some of the applications of this approach could be:

  1. Security testing and regression testing of IoT system
  1. Communicating system security properites in a machine-readable and verifiable format
  1. Documenting results of system's reverse-engineering
  
Toolsaf is an open-source project driven by [Test of Things](https://testofthings.com).
It was originally created as part of Rauli Kaksonen's doctoral thesis [Transparent and tool-driven security assessment for sustainable IoT cybersecurity](https://urn.fi/URN:NBN:fi:oulu-202406264941) under name of 'tdsaf'.
The thesis introduces _Tool-driven security assessment_ (TSDA) to enhance the cybersecurity of 
IoT products and systems.

## How Toolsaf and TSAF work?

The basic idea of TSDA is to first describe the IoT system or product with
the security statement, then verify by tools that the security statement is accurate, and finally use
the statement for differnet purposes.
A security statement provides a machine-readable description of the system's security,
which allows automated verification.

At the moment the security statment is created by Toolsaf using dedicated Python-based _Domain-Specific Language_ (DSL).
(JSON-based format is under development).
Security statement verification is done by running some [supported tools](documentation/Tools.md) and saving their output. Toolsaf uses the tools output to verify that the security statement is accurate.
Some tools perform their own security checks, which can be incorpororated into security statement verdict.

## Getting Started with Toolsaf

The following shows how you start using Toolsaf. 
For this, you need to perform two tasks

  1. Install Toolsaf Python module
  1. Initialize new or copy existing security statement

You need a recent [Python](https://www.python.org/) interpreter, such as 3.10 or newer.
Most linux distributions should already come with a suitable one, the command
name might be `python3` to separate from older Python interpreters.

The installation of Toolsaf is made currently from _Github_ repository, as there is no _PyPi_ package for Toolsaf, yet.
First, clone this repository.
```shell
git clone https://github.com/testofthings/toolsaf.git # HTTPS
# OR
git clone git@github.com:testofthings/toolsaf.git     # SSH
```
Now that Toolsaf if installed, you have to create a directory and a Python virtual environment for your first security statement.
The commands below produce the [expected project structure](documentation/CreatingSecurityStatements.md#project-structure) for your statement.

```shell
mkdir statement-device && cd statement-device
python3 -m venv .venv
source .venv/bin/activate # Activate the virtual environment
mkdir device
touch device/statement.py
```

Toolsaf must be taken into use in the statement's directory with the following command.
(The option `--config-settings editable_mode=strict` is required by some tools to properly work with locally cloned module.)
```shell
pip install -e ../toolsaf/ --config-settings editable_mode=strict
```

Alternatively, you may copy an existing security statement.
On that case you must also create and activate the virtual environment and install Toolsaf module.

If you want to visualize your security statmenets you also need to install [Graphviz](https://graphviz.org/download/).

In the above, we used _venv_ virtual environments, but as security statements are essentially
Python-code, any other environment should work fine.

## Working with Security Statements

To recap, a security statement is Python DSL code in it's own directory, which uses the Toolsaf Python module.
This section explain how to create security statements and then verify them.
As an example, we have created a security statement for the _Deltaco Smart Outdoor Plug_.

There are two basic approaches to build a security statement:

  1. Write the security statement code first, then run tools and verify it
  1. Run tools to collect information first, then write security statement to match that

If you’re the device manufacturer you likely use the former approach, as you (hopefully)
know your products attack surface and other properties.
If you are a security researcher who is reverse-engineering or pen-testing a product,
you have to use the latter approach.

We created the example security statement using the latter approach, as we have learned the
device properties on the go.

The following documents describe security statements in detail:

  - [Creating Security Statements](documentation/CreatingSecurityStatements.md)
  - [Verifying Security Statements](documentation/VerifyingSecurityStatements.md)

## Command Line Options

Toolsaf is a command line tool, which command-line options are listed [here](documentation/CommandLineOptions.md).

## Sample security statements
A security statement for _Ruuvi gateway and tags_ (https://ruuvi.com/) was developed during the PhD research. The statement is in directory `samples/ruuvi/`. The data for verifying the security statement is available for academic research, please request it from Rauli. Remember to tell the goals of the research and the organization performing it. Right to refuse requests is reserved.

The security statement for Ruuvi is executed like this, assuming working directory is the _toolsaf_ root directory:
```
$ python samples/ruuvi/ruuvi.py
```
The command dumps some basic information about the security statement.

## License and contributions

The project is published with [MIT license](LICENSE).

We are happy to accept contributions to Toolsaf, please see the [instructions](documentation/Contributing.md).
