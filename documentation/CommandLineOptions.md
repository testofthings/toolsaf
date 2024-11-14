# Command Line Options
This document covers TDSAF's command-line options.

## Command-Line help
Command-line help is available with the usual `-h` and `--help`. You can use it without loading any model with the following command:
```bash
python tdsaf/main.py --help
```

## Reading Tool Output
Tool output is read from a batch directory with `-r` or `--read`.
```bash
python statements/statement.py -r ../sample-data
```

## Display Verdict Tool Data
The lines/frames, e.g. in a _pcap_ file, that effect verification verdicts can be printed out with `-w` or `--with-files`.
```bash
python statements/statement.py -r ../sample-data -w
```
Example output showing that verdict was made based on a capture's frame 24078:
```
Device    ==> Backend 1 TLS:8886 [Expected/Pass]
@../sample-data/device/pcap-1/capture.pcap:24078
```

## Display Batch Directory Data Type/Tool
```
python statements/statement.py -r ../sample-data --help-tools
```
Example output:
```
nmap      Nmap scan
pcap-0    PCAP reader
pcap-1    PCAP reader
```

## SQL Database
Command line option `--db` connects to an SQL database.
At the moment, the only tested database is (Sqlite)[https://www.sqlite.org/].
For example, to read batch files and put the resulting events into DB:

     $ python statement --db sqlite:///test.db -r <batch-directory>

Existing events are automatically fetched from the database on startup.
For example, the following starts API server with content of the database.


     $ python statement --db sqlite:///test.db --http-server 8180

## TODO:
```
--def-loads DEF_LOADS, -L DEF_LOADS
                    Comma-separated list of tools to load
--dhcp                Add default DHCP server handling
--dns                 Add default DNS server handling
-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --log {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                    Set the logging level
--http-server HTTP_SERVER
                    Listen HTTP requests at port
--test-delay TEST_DELAY
                    HTTP request artificial test delay, ms
--no-auth-ok          Skip check for auth token in TDSAF_SERVER_API_KEY
--test-get TEST_GET   Test API GET, repeat for many
--test-post TEST_POST TEST_POST
                    Test API POST
--log-events          Log events
```