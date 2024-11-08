# Tool-Driven Security Assessment Framework

This is an **early version** of the _Tool-driven security assessment_ (TDSA) framework.
The framework is intended to support automated security assessment of _Internet of Things_ (IoT) and other systems by running common security tools.

This is an open-source project driven by [Test of Things](https://testofthings.com).
It has been developed based on the PhD thesis of Rauli Kaksonen.
Orginally, the project was created to demonstrate the TDSA approach for research purposes, but the goal is to make it a real-world usable security assessment framework.

The framework has two main functions:

  1. _Security statement_ creation for an IoT/IT product or system
  1. Statement verification using output from supported tools

Security statements are currently created with a Python-based _Domain-Specific Language_ (DSL).
The verification is done by running [supported tools](Tools.md), and using their output to pass verdicts on security statement properties.


## Getting Started with TDSAF
At the moment there is no _PyPi_ package for TDSAF, so it must be installed manually. Here's how to do that:

First, clone this repository.
```shell
git clone https://github.com/testofthings/tdsaf.git # HTTPS
# OR
git clone git@github.com:testofthings/tdsaf.git     # SSH
```

Next, create a directory and a virtual environment for your security statement.
```shell
mkdir statement-device
cd statement-device
python3 -m venv .venv
source .venv/bin/activate
```

Finally, TDSAF can be taken into use in the statement's directory with the following command.
```shell
pip install -e ../tdsaf/ --config-settings editable_mode=strict
```

Keep in mind that TDSAF and security statements should be stored in their own separate directories.

## Working with Security Statements
This sections explains how to create security statements for your devices and how to then verify these statements. The explanations also provide examples based on how we created a security statement for the _Deltaco Smart Outdoor Plug_.

### Creating Security Statements
Information on security statement creation is provided [here](documentation/CreatingSecurityStatements.md).

### Verifying Security Statements
Information on security statement verification is provided [here](documentation/VerifyingSecurityStatements.md).

## Usage

Security statement are created by Python [Domain Specific Language (DSL)](DSLIntro.md).
The idea is that security statement are created as Python applications, with one or several statements per application.
Thus, the first thing is to create a Python application project. I recommend creating a _virtual environment_ for the project (there are many guides in the Internet). For example

    $ mkdir my_ss
    $ cd my_ss
    $ python3.12 -m venv .venv
    $ source .venv/bin/activate

After that, you must [install](Install.md) the framework from _Github_.
Then you can start working with you security statement using your favorite editor or IDE.
The framework comes with sample security statements in directory `samples/`. The security statements description are in a [DSL](DSLIntro.md).

Assuming your security statement is `statement.py`, you execute it as follows:

    $ python statement.py

## Providing tool data

Once the security statement is defined, it can be verified.
The verification is tool-driven based on output from the tools. Tool results must be stored in a [batch directory](Tools.md) structure, which is specified by `--read` argument, e.g.
```
$ python statement.py --read <batch-dir>
```

The `--read` and `--http-server` arguments can be combined to inspecft the verification results using the UI.

Batch files can be provided through API in a zip-file to endpoint `api1/batch`.
The content type must be set to `application/zip` and authorization-cookie must be set.
This can be done e.g by `curl`-command, like this:
```
$ curl -v -X POST --data-binary @<batch-file>.zip  \
   -H "Content-Type: application/zip" -b "authorization=xxx" \
   http://localhost:8180/api1/batch
```

## More options

The framework has additional [command-line options](CommandLine.md).

## API server

The framework can run as [API server](APIServer.md).
The server can only run a single security statement or it can dynamically load them by API calls.

The servers are inteded to be run Docker containers.
The containers can bundled into a deployment, see [tcsfw UI](https://github.com/ouspg/tcsfw-ui) documentation.

# Client tool

The API can be used by _client tool_ [tdsaf](ClientTool.md).

## Sample security statements

A security statement for _Ruuvi gateway and tags_ (https://ruuvi.com/) was developed during the PhD research. The statement is in directory `samples/ruuvi/`. The data for verifying the security statement is available for academic research, please request it from Rauli. Remember to tell the goals of the research and the organization performing it. Right to refuse requests is reserved.

The security statement for Ruuvi is executed like this, assuming working directory is the Tdsaf root:
```
$ python samples/ruuvi/ruuvi.py
```
The command dumps some basic information about the security statement.

## Future plans

On the long run the framework is intended to support JSON-based security statement descripitons and cover more different tools.
Check the [roadmap](Roadmap.md) for upcoming features.

## License

The project is published with [MIT license](LICENSE).
