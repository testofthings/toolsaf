# Verifying Security Statements

[Table of contents](README.md)

The security statement of an IoT system or product should be verified.
The verification can take advantage of various tools and it can be automated.
Verifiability comes from machine-readability and mapping of tool output into security statement features.
Verifiability sets aside security statements from informal descriptions, which are bound to be
incomplete and out-of-date.

## Verification Process

During the verification process, the correctness and coverage of the security statement are assessed by comparing it to data collected from the IoT system itself.

Security statement verification is a two-step tool-driven process:

  - The first step is data collection using [tools](Tools.md#list-of-supported-tools) and storing
the tool output.
  - The second step is running the statement's Python file with the `-r` or `--read` [command-line option](CommandLineOptions.md) to read the data and verify the statement.

Data collection requires the System Under Test (SUT) to be available to run the tools.
For best access, the tested IoT devices should be connected to a router or switch which allows the capture of data. This can be e.g. a WiFi-hotspot. The router/switch must be able to intercept the connections between devices and the system's backend services. Mobile devices running related applications should also be connected to the same network as the DUT.

As an example of the data collection setup, here is an image of the system architecture from our Deltaco Smart Outdoor Plug security statement creation process.
![Data collection system architecture image](img/deltaco-smart-plug.png)
In this setup, tools were operated by sending commands from the computer to the WiFi-hotspot over SSH. The tools we used were **_tcpdump_** and **_nmap_**.

Toolsaf expects the tool data to be stored in a specific format, so that it can detect the used tools and read other _metadata_.
The metadata includes at least the IP or HW addresses of the system hosts, so that tool data
can be assigned to the correct hosts and services.
To this end, the collected data must be stored in a [batch directory](Tools.md#batch-files-and-directories) structure.


### Notes on Collecting Network Traffic

When it comes to capturing network traffic with, e.g. tcpdump, start capturing packets before powering on the device or starting mobile applications. This ensures that all relevant data is captured.

## Using Tool Data with Toolsaf

Toolsaf verifies security statements by comparing them to data collected from the system with the [supported tools](Tools.md#list-of-supported-tools) and stored in a [batch directory](Tools.md#batch-files-and-directories). When running a security statement file, tool output is provided to Toolsaf with command-line flags `-r` and `--read`. Here's an example:
```shell
python3 product/statement.py -r ../sample-data/product/
```
In this example, we have a directory called `sample-data` ([batch directory](Tools.md#batch-files-and-directories)) which holds the data collected from the system.

Once a security statement file is run with the tool data, Toolsaf outputs the statement's verification result. Here's an edited example to give you an idea of what the results look like:
```shell
$ python3 product/statement.py -r ../sample-data/product/ -s properties
=======================================================================
Verdict:         System:
-----------------------------------------------------------------------
[Fail]           Example System
=======================================================================
Verdict:         Hosts and Services:
-----------------------------------------------------------------------
[Expected/Pass]  DUT
                 │  Addresses: DUT, 192.168.3.1
[Expected/Pass]  ├──UDP:64144
[Expected/Pass]  ├──ARP
                 └──DUT SW [component]
                    ├──component:dependency version 1.0
                    └──component:...
[Expected/Fail]  Mobile_App
                 │  Addresses: Mobile_App, 192.168.3.3
[Expected/Pass]  ├──TLS:443
[Expected/Fail]  ├──SSH:22
[Pass]           │  └──check:encryption
                 └──Mobile_App SW [component]
[Pass]              └──permission:Billing
[Expected/Pass]  Backend 1
                 │  Addresses: 1.2.3.4 1.2.3.5 Backend_1
[Expected/Pass]  └──TLS:443
...
=======================================================================
Connections
Verdict:         Source:             Target:
-----------------------------------------------------------------------
[Expected/Pass]  DUT                 Backend 1 UDP:63144
[Unexpected/Fail]DUT                 Mobile App SSH:22
[External]       Mobile app          play.googleapis.com TLS: 443
....
```
The output is divided into three main sections: _System_, _Hosts and Services_, and _Connections_. The first displays the overall verdict for the system. The two others list out all the hosts (devices, backends, etc.) and connections you have defined in the security statement, along with connections, found by Toolsaf from tool output, that are not present in the statement.

### Hosts and Services
For each host, Toolsaf displays its name and a corresponding verdict. The verdict consists of two components: a status message and the actual verdict. The status is always `Expected` since the hosts are derived directly from the security statement. The actual verdict, either `Pass` or `Fail`, is determined by aggregating the host verification result with service verdicts.

A list of addresses is below each host name. The addresses include DNS names, HW addresses, IP addresses, etc. For each host, a special _tag_ address is given, derived from the component name. In the example above, these are `DUT`, `Mobile_App`, and `Backend_1` are tag addresses. Tag addresses are useful in batch metafiles to identify the host or address. Several IP addresses are listed as defined in the metafiles. Backend 1's address includes also DNS name specified in the security statement.

Listed next are the services, comprising protocols and ports, used in communications to and from the host. For these, the verdict can be:
| Verdict | Description |
|---------|-------------|
| `External`      | Related host/service is part of testing infrastructure or otherwise not part of the system itself |
| `Expected`      | Listed in the security statement, but not observed in collected data |
| `Expected/Fail` | Listed in the security statement, but verification by data failed |
| `Expected/Pass` | Listed in the security statement and verified by data |

A set of _properties_ can be listed for hosts and services.
These properties can include, e.g. software dependencies from a SBOM, mobile application permissions,
and issues raised by tools, among other things.
The properties can be given `Pass` or `Fail` verdicts, which then propagate to the service and host verdicts.

### Connections

Toolsaf details individual connections by displaying their verdict, source, and target. The target section also includes the top-level protocol and target port used in the connection.

Connection verdicts can have any of the following:
| Verdict | Description |
|---------|-------------|
| `External`        | Connection to/from host other than the DUT not listed in the security statement |
| `Expected`        | Listed in the security statement but not present in data |
| `Expected/Fail`   | Listed in the security statement, present in data, has at least one verdict `Fail` property |
| `Expected/Pass`   | Listed in the security statement, present in data |
| `Unexpected/Fail` | Connection to/from the DUT not listed in the security statement |
| `Logical`         | Connection does not represent a physical connection and thus cannot be verified |

Connection properties and their verdicts are listed below their respective connections. Connection properties can include, e.g. [certmitm](Tools.md#certmitm) results.
