# Command line options

This document goes through some command-line options for the [tcsfw](README.md).

As default, the loaded model is printed out. Consider the following, which prints out the samplem model "Basic A".

```
$ python samples/basic-a/system.py
```

## Command-line help

Command-line help is available with the usual `--help`. Below it is used without loading any model.

```
$ python tcsfw/main.py --help
```

## SQL database

Command line option `--db` connect to SQL database.
At the moment, the only tested database is (Sqlite)[https://www.sqlite.org/].
For example, to read batch files and put the resulting events into DB:

     $ python statement --db sqlite:///test.db -r <batch-directory>

Existing events are automatically fetched from the database on startup.
For example, the following starts API server with content of the database.


     $ python statement --db sqlite:///test.db --http-server 8180

## Requirement coverage

Coverage for default requirements (called _claims_ or _tests_ in research papers) can be checked like this:
Please note, requirement coverage if very much in prototype phase.

```
$ python samples/basic-a/system.py --output coverage
```

The used specification can be changed from the default. Currently the only one is `etsi-ts-103-701`.

```
$ python samples/basic-a/system.py --output coverage:etsi-ts-103-701
```

