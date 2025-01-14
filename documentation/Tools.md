# Tools
TDSAF can read output from various tools to verify security statements. Tool output is organized in a directory structure, with the root directory specified to the framework using the `--read <directory>` command-line argument.

## Batch files and directories
The batch directory structure can be arbitarily deep. Each directory containing data files must have a special metafile `00meta.json`. Metafiles must always contain at least the `file_type` of related data files. For example, consider the following `00meta.json` for NMAP output data files.
```json
{
    "file_type": "nmap"
}
```
The data files have to usually be named according to the template dictated by file type. The templates are discussed below with file types.

Each batch directory also has a _label_, which allows TDSAF to filter the processed data. By default, the _label_ is the name of the directory, but it can be changed in the metafile, e.g. the following NMAP data is filtered by label `nmap-01`.
```json
{
    "file_type": "nmap",
    "label": "nmap-01"
}
```

Here is an exaple batch directory structure:
```
sample-data
├── nmap-0
│   ├── 00meta.json
│   └── nmap_scan.xml
├── pcap-0
│   ├── 00meta.json
│   └── capture.pcap
└── pcap-1
    ├── 00meta.json
    └── capture.pcap
```

See [end of this page](#advanced-metafile-definitions) for advanced options required with some data types.

## List of supported tools

In the following list you can find the tools and formats TDSAF supports. Short descriptions and commands for output capturing in proper formats are provided in their own sections.

| Tool | File Format |
|------|-------------|
| [apktool](Tools.md#android-manifest) | .xml |
| [Black Duck Vulns](Tools.md#black-duck-vulnerabilities) | .csv |
| [Censys](Tools.md#censys) | .json |
| [certmitm](Tools.md#certmitm) | .zip |
| [GitHub Releases](Tools.md#github-releses) | .json |
| [HAR](Tools.md#har) | .json |
| [MITM proxy](Tools.md#mitm-proxy) | .log |
| [nmap](Tools.md#nmap) | .xml |
| [Wireshark / tcpdumo](Tools.md#pcap) | .pcap |
| [SPDX SBOM](Tools.md#spdx) | .json |
| [ssh-audit](Tools.md#ssh-audit) | .json |
| [testssl.sh](Tools.md#testsslsh) | .json |
| [Tshark (BLE only)](Tools.md#tshark-ble-only) | .json |
| [cURL](Tools.md#http-responses) | .http |
| [ZED Attack Proxy (ZAP)](Tools.md#zed-attack-proxy-zap) | .json |

### Android Manifest
TDSAF checks the permissions listed in `.xml` format Android Manifest files. These can be extracted from mobile application's `.apk` files. Example metafile `00meta.json`:

```json
{
    "file_type": "apk"
}
```
A manifest file can be extracted from an Android package file with `apktool` or simply using 'unzip'.
```
$ apktool d <package>.apk -f -o apk-files
```
The file can be found from `apk-file/AndroidManifest.xml`.
As the package file is a zip, the following works as well.
```
$ unzip <package>.apk AndroidManifest.xml
```
We divide Android permissions into [different categories](../tdsaf/adapters/data/android_permissions.json) that are then used in the DSL.

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
$ python tdsaf/censys_scan <address>
```

### Certmitm
[Certmitm](https://github.com/aapooksman/certmitm) produces files and folders as its output. To provide this data to TDSAF, create a compressed `.zip` file containing the output.
Example metafile `00meta.json`:
```json
{
    "file_type": "certmitm",
    "addresses": {
        "192.168.4.2": "Mobile_App",
        "192.168.5.3": "Backend_1"
    }
}
```
To properly process certmitm results, IP addresses for the hosts, present in the output need to be provided in the metafile.

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

### Shodan
Data files are JSON format Shodan scan results with suffix `.json`. Example metafile `00meta.json`:
```json
{
    "file_type": "shodan"
}
```
If there are no Wireshark captures that are processed before the Shodan results, add the `addresses` section to the metafile, so that results are connected correctly.

Shodan scan results can be obtained by using either of the following commands:
```bash
export SHODAN_API_KEY=your-api-key

python3 tdsaf/adapters/shodan_scan.py iplookup 8.8.8.8 # Results for one IP
# OR
python3 tdsaf/adapters/shodan_scan.py dnslookup ruuvi.com # Results for multiple IPs under given domain
```

### SPDX

Data is Software Package Data Exchange (SPDX) json-files with suffix `.json`.
Example metafile `00meta.json`:
```json
{
    "file_type": "sdpx"
}
```

SPDX file import is tested with files downloaded from Black Duck service. You can also use open-source SBOM generators to create `.json` format SPDX files.

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

Note, only BLE data is read from JSON-formatted capture. The  command-line tool `tshark` can capture data in this format and convert pcap-files to it. See `tshark` documentation for instructions.

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
$ (echo "<url>"; curl -Li <url>) > <file-name>.http
```
NOTE: The first line of the `.http` file must contain the pages URL starting with `https://` or `http://`. The second line must contain the requests status code.

### ZED attack proxy (ZAP)

Data is output from _ZED attack proxy_ (ZAP) tool named as `<address>.json` where `<address>` is the host address.
Example metafile `00meta.json`:
```json
{
    "file_type": "zap"
}
```

See the tool manual for how to save scanning data.

## Other metafile definitions

Addresses of the hosts can be defined in metafiles.
Definitions in parent directories apply in sub-directory metafiles.
The following shows how addresses can be customized per batch directory.
```json
{
    "file_type": "mitmproxy",
    "addresses": {
        "192.168.4.8": "Ruuvi_app",
        "30:c6:f7:52:db:5d|wd": "Ruuvi_Gateway",
    }
}
```

External activity policy detemines the type of unexpected external connections allowed for a host or services.
The following shows how to allow UNLIMITED external connections if host is a router etc. in a data batch.
```json
{
    "file_type": "capture",
    "external_activity": {
        "Ruuvi_Gateway": "UNLIMITED"
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
