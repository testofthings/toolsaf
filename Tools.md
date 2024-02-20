# Tools

The tcsfw can read output from several different tools to verify the security statement and claims.
The tool output is read from a directly structure, which root must be provided to the framework by `--read <directory>` command-line arguement.

## Batch files and directories

The back directory structure can be arbitarily deep. Each directory which contains data files, must have special metafile `00meta.json`. The metafile must always contain at least `file_type` of the data files. For example, consider the following metafile `00meta.json` for NMAP output data files.

```json
{
    "file_type": "nmap"
}
```
The data files have to usually be named according the template dictated by file type. The templates are discussed below with file types.

Each batch directory has also _label_, which allows to filter the processed data.
By default, label is the name of the directory, but it can be changed in the metafile, e.g. the following NMAP data is filtered by label `nmap-01`.
```json
{
    "file_type": "nmap",
    "label": "nmap-01"
}
```

See [end of this page](#advanced-metafile-definitions) for advanced options required with some data types.

## List of supported tools

The following lists the supported tools and formats and shortly describes what is actually supported.
A sample command to capture the output in proper format is shown for command-line tools.

### Android Manifest

Data files are APK manifest XML files with suffix `.xml`.
Example metafile `00meta.json`:

```json
{
    "file_type": "apk"
}
```

A manifest file can be extracted from Android package file by `apktool' or simply using 'unzip'.

```
$ apktool d <package>.apk -f -o apk-files
```
The file can be found from `apk-file/AndroidManifest.xml`.
As the package file is a zip, the following works as well.
```
$ unzip <package>.apk AndroidManifest.xml
```

### Black Duck vulnerabilities

Data files are csv-files downloaded from Black Duck binary analyser and named as `<component>.csv` where `<component>` is the name of the SW component.
Example metafile `00meta.json`:

```json
{
    "file_type": "blackduck-vulnerabilities"
}
```

### Censys

Data files are json-files fetched by Censys search API and named as `<address>.json` where `<address>` is address of the scanned remote host.
Example metafile `00meta.json`:

```json
{
    "file_type": "censys"
}
```

Use of Censys API requires an account with suitable permissions. Once account has been set up property, the framework utility can be used to fetch the JSON through API:
```
$ python tcsfw/censys_scan <address>
```

### Github releses

Data files are release json-files fetched from GitHub and named as `<component>.json` where `<component>` is the name of the SW component.
Example metafile `00meta.json`:

```json
{
    "file_type": "github-releases"
}
```

### HAR

Data files are HAR json-files saved by browser and named as `<host>.json` where `<host>` is the name of the browsing host.
Example metafile `00meta.json`:

```json
{
    "file_type": "har"
}
```
Chrome can save HAR-files compatible with the reader.
The way to save HAR-file depends on the browser.

### MITM proxy

Data files are custom log-files captured with MITM proxy having suffix  `.log`. Example metafile `00meta.json`:
```json
{
    "file_type": "mitmproxy"
}
```

The custom data is saved using the following very simple MTIM proxy addon hook (yes, very unsatisfactory, sorry):

```python
import logging
from datetime import datetime

class TLSCheck:
    """Log connection attempts with possible error message"""
    def tls_established_client(self, data):
        conn = data.conn
        ser = data.context.server
        logging.info("tls_established,%s,%d,%s,%d,%s,%s",
            conn.peername[0], conn.peername[1],
            ser.peername[0], ser.peername[1],
            conn.sni or "", conn.error or "")

    def tls_failed_client(self, data):
        conn = data.conn
        ser = data.context.server
        logging.info("tls_failed,%s,%d,%s,%d,%s,%s",
            conn.peername[0], conn.peername[1],
            ser.peername[0], ser.peername[1],
            conn.sni or "", conn.error or "")


addons = [TLSCheck()]
```

Refer MITM proxy documentation how to use addon hooks.

### Nmap

Data files are Nmap XML-formatted output files with suffix `.xml`. Example metafile `00meta.json`:
```json
{
    "file_type": "nmap"
}
```
The nmap-command is ran in the following manner to capture the data:

```
$ nmap -oX <file>.xml <target>
```

### PCAP

Data files are PCAP (not pcap-ng) files with suffix `.pcap`. Example metafile `00meta.json`:
```json
{
    "file_type": "pcap"
}
```

Files can be captured by _Wireshark_ or `tcpdump`, see their documentation for instructions.

### SPDX

Data is Software Package Data Exchange (SPDX) xml-files with suffix `.xml`.
Example metafile `00meta.json`:
```json
{
    "file_type": "sdpx"
}
```

SPDX file import is tested with files downloaded from Black Duck service.

### Ssh-audit

Data is output from `Ssh-audit` tool named as `<address>.<port>.json` where `<address>` is the host address and `<port>` is TCP port number.
Example metafile `00meta.json`:
```json
{
    "file_type": "ssh-audit"
}
```

See the tool manual for how to save scanning data.

### Testssl.sh

Data is output from `Testssl.sh` tool named as `<address>.<port>.json` where `<address>` is the host address and `<port>` is TCP port number.
Example metafile `00meta.json`:
```json
{
    "file_type": "testssl"
}
```

See the tool manual for how to save scanning data.

### Tshark (BLE only)

Data files are `tshark` command JSON-formatted PCAP of Bluetooth Low-Energy (BLE) traffic with suffix `.json`.
Example metafile `00meta.json`:
```json
{
    "file_type": "capture-json"
}
```

Note, only BLE data is read from JSON-formatted papture. The  command-line tool `tshark` can capture data in this format and convert pcap-files to it. See `tshark` documentation for instructions.

### HTTP responses

Data files are the HTTP requests and their payloads with suffix `.http`.
Example metafile `00meta.json`:
```json
{
    "file_type": "http"
}
```

Files can be saved e.g. by `curl` with following syntax where `<url>` is the service URL.
```
$ curl -L -i -o <url>.http <url>
```
NOTE: The actual save file name must be URL-encoded (`%3a` for dot, etc.)!

### ZED attack proxy (ZAP)

Data is output from _ZED attack proxy_ (ZAP) tool named as `<address>.json` where `<address>` is the host address.
Example metafile `00meta.json`:
```json
{
    "file_type": "zap"
}
```

See the tool manual for how to save scanning data.

## Advanced metafile definitions

Sometimes IP or HW addresses change between tool runs.
The following shows how addresses can be customized per batch directory.
```json
{
    "file_type": "mitmproxy",
    "addresses": {
        "192.168.4.8": "Ruuvi app",
        "30:c6:f7:52:db:5d|wd": "Ruuvi Gateway",
    }
}
```

External activity policy detemines the type of unexpected external connections allowed for a host or services.
The following shows how to allow UNLIMITED external connections if host is a router etc. in a data batch.
```json
{
    "file_type": "capture",
    "external_activity": {
        "Ruuvi Gateway": "UNLIMITED"
    }
}
```

Network node names and addresses are learned from captures and other data. Sometimes, this must happen before some other data batch can be successfully read.
Normally directories and files are read in alphabetical order, which may not be correct.
The following shows how to force specific directories to be read first. Unlisted directories are read after specified ones.

```json
{
   "file_order": ["pcap-prefix", "pcap-data"]
}
```
