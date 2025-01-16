# Verifying Security Statements
During the verification process, the correctness and coverage of the security statement are assessed by comparing it to data, collected by [various tools](Tools.md), from the actual system.

As such, security statement verification is a two-step tool-driven process. It starts with data collection using any of the [supported tools](Tools.md#list-of-supported-tools) and ends with running the statement's Python file with the `-r` or `--read` [command-line flag](CommandLineOptions.md). This document explains this process.

## Collecting Tool Data
Data collection requires the Device Under Test (DUT) to be connected to a router or switch which allows the capture of data. This can be e.g. a WiFi-hotspot. The router / switch must be able to access the system's backend services. Mobile devices running related applications should also be connected to the same network as the DUT.

As an example of the data collection setup, here is an image of the system architecture from our Deltaco Smart Outdoor Plug security statement creation process.
![Data collection system architecture image](img/deltaco-smart-plug.png)
In this setup, tools were operated by sending commands from the computer to the WiFi-hotspot over SSH. The tools we used were **_tcpdump_** and **_nmap_**.

The collected data is stored to a [batch directory](Tools.md#batch-files-and-directories).

## Notes on Collecting Different Types of Data
### Network Traffic
When it comes to capturing network traffic with, e.g. tcpdump, start capturing packets before powering on the device or starting mobile applications. This ensures that all relevant data is captured.

## Using Tool Data with Toolsaf
Toolsaf verifies security statements by comparing them to data collected from the system with any of the [supported tools](Tools.md#list-of-supported-tools). When running a security statement file, tool output is provided to Toolsaf with command-line flags `-r` and `--read`. Here's an example:
```shell
python3 product/statement.py -r ../sample-data/product/
```
In this example, we have a directory called `sample-data` ([batch directory](Tools.md#batch-files-and-directories)) which holds the data collected from the system. Toolsaf also requires that `00meta.json` files are present in the batch directory. More details on these JSON files are available [here](Tools.md#batch-files-and-directories).

## Checking Toolsaf Output
Once a security statement file is run with either one of the _read_ flags, Toolsaf outputs the statement's verification result. Here's an example to give you a rough idea what the results look like:
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
                 │  Addresses: DUT
[Expected/Pass]  ├──UDP:64144
[Expected/Pass]  ├──ARP
                 └──DUT SW [component]
                    ├──component:dependency version 1.0
                    └──component:...
[Expected/Fail]  Mobile_App
                 │  Addresses: Mobile_App
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
The output is divided into three main sections: _System_, _Hosts and Services_ and _Connections_. The first displays the overall verdict for the system. The two others list out all the hosts (devices, backends, etc.) and connections you have defined in the security statement, along with connections, found by Toolsaf from tool output, that are not present in the statement.

### Hosts and Services
For each host, Toolsaf displays its name and a corresponding verdict. The verdict consists of two components: a status message and the actual verdict. The status is always `Expected` since the hosts are derived directly from the security statement. The actual verdict, either `Pass` or `Fail`, is determined by aggregating the verdicts of the host's individual properties and connections.

Below a host's name, its addresses are listed. The addresses can include DNS names, one or more IP address, and aliases defined in `00meta.json`. In the example above, addresses for the DUT and Mobile App are listed as `DUT` and `Mobile_App`, as they were defined in `00meta.json`. Backend 1's address list includes the IP addresses Toolsaf found for it from a network traffic capture. Backend 1 was also defined in `00meta.json` so its address list includes `Backend_1`, and its DNS name provided in the security statement.

Listed next are the top-level protocols and ports used in communications to and from the host. For these, the verdict can be:
| Verdit | Description |
|--------|-------------|
| `External`      | Related host/service is part of testing infrastructure, not part of the system itself |
| `Expected`      | Listed in security statement, not observed in collected data |
| `Expected/Fail` | Listed in security statement, observed in data, has at least one vedict `Fail` property |
| `Expected/Pass` | Listed in security statement, observed in data |

If additional properties for top-level protocols were found from the data or were included in the statement, they will be listed below the specific protocol along with their verdicts.

Listed lastly for the hosts, are their software components and their properties. These properties can include, e.g. software dependencies from a Software Bill of Materials or mobile application permissions. The properties are also given `Pass` or `Fail` verdicts.

### Connections
Toolsaf details individual connections by displaying their verdict, source, and target. The target section also includes the top-level protocol and target port used in the connection.

Connection verdicts can have any of the following:
| Verdit | Description |
|--------|-------------|
| `Logical`         | **FIXME** |
| `External`        | Connection to/from host other than the DUT not listed in the security statement |
| `Expected`        | Listed in security statement but not present in data |
| `Expected/Fail`   | Listed in security statement, present in data, has at least one verdict `Fail` property |
| `Expected/Pass`   | Listed in security statement, present in data |
| `Unexpected/Fail` | Connection to/from the DUT not listed in security statement |

Connection properties and their verdicts are listed below their respective connections. Connection properties can include, e.g. [certmitm](Tools.md#certmitm) results.

## TODO
- Add description for `Logical` connection in the table of the **Connections** section.