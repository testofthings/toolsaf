## Verifying Security Statements
Security statement verification is a two-step process. It starts with data collection using any of the [supported tools](../Tools.md#list-of-supported-tools) and ends with running the statement's Python file with the `-r` or `--read` command-line flag. This document explains this process.

### Collecting Tool Data
Data collection requires the Device Under Test (DUT) to be connected to a WiFi-hotspot from which data can be collected. The WiFi-hotspot must be able to access the system's backend services. Mobile devices with related applications should also be connected to the same hotspot as the DUT.

As an example of the data collection setup, here is an image of the system architecture from our Deltaco Smart Outdoor Plug security statement creation process.
![Data collection system architecture image](img/deltaco-smart-plug.png)
In this example, tool running commands were entered on the computer which was connected to the WiFi-hotspot over SSH.

### Notes on Collecting Different Types of Data
#### Network Traffic
When it comes to capturing network traffic with, e.g. tcpdump, the capturing should be started before mobile apps and devices in the system are turned on. This way no important information is missed.

### Using Tool Data with TDSAF
TODO (-r flag)

### Checking TDSAF Output
TODO (Pass or Failed)
