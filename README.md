# Toolsaf
This is an **early version** of Toolsaf, a tool driven security assesment framework.
The framework is intended to support automated security assessment of _Internet of Things_ (IoT) and other systems by running common security tools.

This is an open-source project driven by [Test of Things](https://testofthings.com).
It has been developed based on the PhD thesis of Rauli Kaksonen.
Orginally, the project was created to demonstrate the TDSA approach for research purposes, but the goal is to make it a real-world usable security assessment framework.

The framework has two main functions:

  1. _Security statement_ creation for an IoT/IT product or system
  1. Statement verification using output from supported tools

Security statements are currently created with a Python-based _Domain-Specific Language_ (DSL).
The verification is done by running [supported tools](documentation/Tools.md), and using their output to pass verdicts on security statement properties.

## Getting Started with Toolsaf
At the moment there is no _PyPi_ package for Toolsaf, so it must be installed manually. Here's how to do that:

First, clone this repository.
```shell
git clone https://github.com/testofthings/toolsaf.git # HTTPS
# OR
git clone git@github.com:testofthings/toolsaf.git     # SSH
```

Next, create a directory and a virtual environment for your security statement.
```shell
mkdir statement-device && cd statement-device
python3 -m venv .venv
source .venv/bin/activate # Activate the virtual environment
mkdir device && cd device
touch __init__.py statement.py
```
The above commands produce the [expected project structure](documentation/CreatingSecurityStatements.md#project-structure) for your statement.

Finally, Toolsaf can be taken into use in the statement's directory with the following command.
(The option `--config-settings editable_mode=strict` is required by some tools to properly work with locally cloned module.)
```shell
pip install -e ../toolsaf/ --config-settings editable_mode=strict
```

Keep in mind that Toolsaf and security statements should be stored in their own separate directories.

If you want to visualize your security statmenets you also need to install [Graphviz](https://graphviz.org/download/).

## Working with Security Statements
The following two subsections explain how to create security statements for your devices and then verify them. The explanations also provide examples based on how we created a security statement for the _Deltaco Smart Outdoor Plug_.

If you’re a device manufacturer, begin with the creation section. If you’re less familiar with the inner workings of the device you want to test, start with the verification section, which covers data collection. A security statement can be created based on collected data (as we did with the Smart Outdoor Plug).

### Creating Security Statements
Information on security statement creation is provided [here](documentation/CreatingSecurityStatements.md).

### Verifying Security Statements
Information on security statement verification is provided [here](documentation/VerifyingSecurityStatements.md).

## Command Line Options
The framework's command-line options are listed [here](documentation/CommandLineOptions.md).

## Sample security statements
A security statement for _Ruuvi gateway and tags_ (https://ruuvi.com/) was developed during the PhD research. The statement is in directory `samples/ruuvi/`. The data for verifying the security statement is available for academic research, please request it from Rauli. Remember to tell the goals of the research and the organization performing it. Right to refuse requests is reserved.

The security statement for Ruuvi is executed like this, assuming working directory is the _toolsaf_ root directory:
```
$ python samples/ruuvi/ruuvi.py
```
The command dumps some basic information about the security statement.

## Unit Test
To run the unit tests, install _pytest_
```shell
pip install pytest
```
then:
```shell
pytest tests/
```

## Linting
To lint toolsaf code, install _pylint_
```shell
pip install pylint
```
then:
```shell
pylint toolsaf/
```
Samples and tests are not lint-compatible.

## Future plans
In the long run the framework is intended to support JSON-based security statement descripitons and to cover even more tools. Check the [roadmap](Roadmap.md) for upcoming features.

## License
The project is published with [MIT license](LICENSE).
