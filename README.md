# Tcsfw

This is **early version** of the _Tool-driven security assessment_ (TDSA) framework.
The framework is intended to support automated security assessment of _Internet of Things_ (IoT) and other systems by running common security tools.
(The name is acronym from _Transparent Cybersecurity Framework_, which is name used in a research paper, but things have developed and the name is TDSA now.)

The project is part of the upcoming PhD thesis of the author.
Orginally, the project was created to demonstrate the TDSA approach for research purposes, but the goal is to make it a real-world usable security assessment 
framework.
The research will be published in the PhD disseration, which is under works.
On the mean time, there are two published research papers:

> Kaksonen, R., Halunen, K., Laakso, M., & Röning, J. (2023). Transparent Security Method for Automating IoT Security Assessments. In The 18th International Conference on Information Security Practice and Experience (ISPEC). Springer International Publishing.

> Kaksonen, R., Halunen, K., Laakso, M., & Röning, J. (2024). Automating IoT Security Standard Testing by Common Security Tools. In ICISSP - 10th International Conference on Information Systems Security and Privacy. (p. 42-53). SciTePres

The functionality of the framework is currently limited to reading output of several different "security" tools, mapping them into _security statement_ and _claims_, and given verdicts for the claims. Security statement describes relevant portions of a system, e.g. attack surface and security controls. Claim (requirement, test) is security-relevant assertion which can be verified. The verification is done by running [supported tools](Tools.md), which output is them used to pass verdict for the claim.

## Future plans

On the long run the framework is intended to cover the collection of the tool outputs and provide more rich processing options and API for the claim verdicts.
Check the [roadmap](Roadmap.md) for upcoming features.

## Usage

Security statement are created by Python [Domain Specific Language (DSL)](DSLIntro.md). 
The idea is that security statement are created as Python applications, with one or several statements per application.
Thus, the first thing is to create a Python application project. I recommend creating a _virtual environment_ for the project (there are many guides in the Internet). For example

    $ mkdir my_ss
    $ cd my_ss
    $ python 3.11 -m venv create .venv
    $ source .venv/bin/activate

After that, you must [install](Install.md) the framework from _Github_.
Then you can start working with you security statement using your favorite editor or IDE.
The framework comes with sample security statements in directory `samples/`. The security statements description are in a [Domain Specific Language (DSL)](DSLIntro.md).

Assuming your security statement is `statement.py`, you execute it as follows:

    $ python statement.py

Security statement can be rendered into visual description using [tcsfw UI](https://github.com/ouspg/tcsfw-ui). The UI is simple Vue-project. The UI uses API provided by the framwork. The API is activated in following manner, with access token `xxx`. See UI documentation how it is set up.
```
$ TCSFW_SERVER_API_KEY=xxx python statement.py --http-server 8180
```

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

## Sample security statements

A security statement for _Ruuvi gateway and tags_ (https://ruuvi.com/) was developed during research. The statement is in directory `samples/ruuvi/`. The data for verifying the security statement is available for academic research, please request it from Rauli. Remember to tell the goals of the research and the organization performing it. Right to refuse requests is reserved.

The security statement for Ruuvi is executed like this, assuming working directory is the Tcsfw root:
```
$ python samples/ruuvi/ruuvi.py
```
The command dumps some basic information about the security statement.
## Docker container

You can build a docker container with the security statement and run it stand-alone or in a simple deployment, see [tcsfw UI](https://github.com/ouspg/tcsfw-ui) documentation.

Your `Dockerfile` should look something like this:
```Dockerfile
FROM python:3.11-slim

WORKDIR /app

# install dependencies without caching
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# install framework
COPY tcsfw /app/tcsfw
COPY setup.py /app
RUN pip install --no-cache-dir -e .

# copy security statements file(s)
COPY statement.py /app

# run the entry point
# ENV TCSFW_SERVER_API_KEY= # set in compose etc.
CMD ["python", "tcsfw/launcher.py", "--listen-port", "8180"]
```

This container is built and started as follows:

    $ docker build -t tcsfw/api-server .
    $ docker run -it -p 8180:8180 tcsfw/api-server

Instead of the security statement `.py` file, the entry point to the container is _launcher_ `tcsfw/launcher.py`.
Launcher accepts incoming requests and starts security statement instances with local DB.
The request url must be `statement/` appended by the statement file path and name without `.py`.
Each new statement runs in separate process in different local API port from range 10000-19999.
For example, the following accesses the security statement from above example:
http://localhost:8180/statements/statement.

See instructions in [tcsfw UI](https://github.com/ouspg/tcsfw-ui) documentation how to use the container with _Docker compose_.

## License

The project is published with [MIT license](LICENSE).

