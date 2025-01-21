# Command Line Options
[Table of contents](README.md)

This document covers Toolsaf's command-line options.

## Command-Line Help
Command-line help is available with the usual `-h` and `--help`. You can use it without loading any model with the following command:
```shell
python toolsaf/main.py --help
```

## Reading Tool Output
Tool output is read from a batch directory with `-r` or `--read`.
```shell
python statements/statement.py -r ../sample-data
```

## Load Only Specific Data
You can limit the sample data used for verification by label or directory name with `-L` and `--def-loads`. Use a comma-separated list.
```shell
# Only load data from pcap-0 and pcap-1
python statements/statement.py -r ../sample-data -L pcap-0,pcap-1
```
By adding `^` to the statement, you can exclude a specific set of data.
```shell
# Use everything but pcap-0
python statements/statement.py -r ../sample-data -L ^pcap-0
```

## Show
By default, properties, hosts, services, and connections considered irrelevant for the assessment are not shown. You can include them in the output by using `-s` or `--show` along with the comma-separated values `all`, `properties`, `ignored`, and `irrelevant`.
```shell
python statements/statement.py -r ../sample-data --show properties,ignored,irrelevant
```
When using `all`, all information is printed without text truncation.

## No Text Truncation
By default, text that is longer than the terminal's width is truncated. This can be turned off with `--no-truncate`.
```shell
python statements/statement.py -r ../sample-data --no-truncate
```

## Use Color With Output Piping
If you want to have text coloring in piped output, use `-c` or `--color`.
```shell
python statements/statement.py -r ../sample-data -c | less -R
```

## Display Verdict Tool Data
The lines/frames, e.g., in a _pcap_ file, that affect verification verdicts can be printed out with `-w` or `--with-files`.
```shell
python statements/statement.py -r ../sample-data -w
```
Example output showing that a verdict was made based on a capture's frame 24078:
```
Device    ==> Backend 1 TLS:8886 [Expected/Pass]
@../sample-data/device/pcap-1/capture.pcap:24078
```

## Display Batch Directory Data Type/Tool
```shell
python statements/statement.py -r ../sample-data --help-tools
```
Example output:
```
nmap      Nmap scan
pcap-0    PCAP reader
pcap-1    PCAP reader
```

## Create Diagram Visualization
You can create a diagram based on your security statement with `-C` or `--create-diagram`. The diagram will not be automatically displayed with this command. You can also set the diagram's file format with this flag. The format can be `png`, `jpg`, `svg`, or `pdf`. The default format is `png`.
```shell
python statements/statement.py --create-diagram
# OR
python statements/statement.py -C jpg
```
Diagram creation requires you to install [Graphviz](https://graphviz.org/download/).

## Create and Show Diagram Visualization
You can use `-S` or `--show-diagram` to create and display a diagram based on your security statement. You can also set the diagram's file format with this flag. The format can be `png`, `jpg`, `svg`, or `pdf`. The default format is `png`.
```shell
python statements/statement.py --show-diagram
# OR
python statements/statement.py -S pdf
```

## Diagram Name
You can set the file name for created diagrams with `-N` or `--diagram-name`.
```shell
python statements/statement.py --create-diagram --diagram-name my_diagram
# OR
python statements/statement.py --show-diagram -N my_diagram
```

## Set Log Level
You can set the log level with `-l` or `--log-level`. Values can be `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.
```shell
python statements/statement.py -r ../sample-data -l INFO
```

## Log Events
By using `--log-events`, you can display all events in the tool data.
```shell
python statements/statement.py -r ../sample-data --log-events
```

## SQL Database
The command-line option `--db` connects to an SQL database.
At the moment, the only tested database is [SQLite](https://www.sqlite.org/).
For example, to read batch files and put the resulting events into a DB:
```shell
python statement --db sqlite:///test.db -r <batch-directory>
```

Existing events are automatically fetched from the database on startup.
For example, you can run a statement with a DB's content:
```shell
python statement --db sqlite:///test.db
```

## FIXME:
```shell
--dhcp                Add default DHCP server handling
--dns                 Add default DNS server handling
```