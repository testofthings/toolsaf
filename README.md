# tcsfw

This project is **proof-of-concept** _Tool-driven security assessment_ (TDSA) framework created for research.
It is only intended to demonstrate the TDSA approach for research and not useful in the real world.
(The name is acronym from _Transparent Cybersecurity Framework_, which is name used for this in a research paper, but I have moved on with the name and it is TDSA now).

The idea behind the framework is published in two research papers:

> Kaksonen, R., Halunen, K., Laakso, M., & Röning, J. (2023). Transparent Security Method for Automating IoT Security Assessments. In The 18th International Conference on Information Security Practice and Experience (ISPEC). Springer International Publishing.

> Kaksonen, R., Halunen, K., Laakso, M., & Röning, J. (2024). Automating IoT Security Standard Testing by Common Security Tools. In ICISSP - 10th International Conference on Information Systems Security and Privacy. (p. 42-53). SciTePres

The functionality of the framework is now reading output of several different "security" tools, mapping them into _security statement_ and _claims_, and given verdicts for the claims. Security statement describes relevant portions of a system, e.g. attack surface and security controls. Claim (requirement, test) is security-relevant assertion which can be verified. The verification is done by running [supported tools](Tools.md), which output is them used to pass verdict for the claim.

Before use, you must [install](Install.md) the framework from _Github_.

The framework comes with sample security stateuments in directory `samples/`. The security statements descriptin are in a [Domain Specific Language (DSL)](DSLIntro.md).
The description of the claims also employs [a DSL](ClaimIntro.md), but that is very much unmature at the moment.

The one used in the research is the security statement for _Ruuvi gateway and tags_ (https://ruuvi.com/) which is used in the research. The statement is in directory `samples/ruuvi/`. The data for verifying the security statement is available for academic research, please request it from Rauli. Remember to tell the goals of the research and the organization performing it. Right to refuse requests is reserved.

Security statements are described by Python-based DSLs. A description is executable Python script. The security statement for Ruuvi is executed like this, assuming working directory is the project root:
```
$ python samples/ruuvi/ruuvi.py
```
The command dumps some basic information about the security statement.

Security statement can be rendered into visual description using [tcsfw UI](https://github.com/ouspg/tcsfw). The UI is simple Vue-project. The UI uses API provided by the framwork. The API is activated in following manner, with access token `xxx`. See UI documentation how it is set up.
```
$ TCSFW_SERVER_API_KEY=xxx python samples/ruuvi/ruuvi.py \
    --http-server 8180
```

Once the security statement is defined, it can be verified.
The verification is tool-driven based on output from the tools. Tool results must be stored in a [batch directory](Tools.md) structure, which is specified by `--read` argument, e.g.
```
$ python samples/ruuvi/ruuvi.py --read <batch-directory>
```

The `--read` and `--http-server` arguments can be combined to inspecft the verification results using the UI.

The framework has additional [command-line options](CommandLine.md).
