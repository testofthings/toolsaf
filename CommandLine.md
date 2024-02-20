# Command line options

This document goes through some command-line options for the [tcsfw](README.md).

As default, the loaded model is printed out. Consider the following, which prints out the samplem model `iot-a`.

```
$ python samples/iot-a/system.py
```

## Command-line help

Command-line help is available with the usual `--help`. Below it is used without loading any model.

```
$ python tcsfw/main.py --help
```

## Requirement coverage

Coverage for default requirements (called _claims_ or _tests_ in research papers) can be checked like this:

```
$ python samples/iot-a/system.py --output coverage
```

The used specification can be changed from the default. Currently the only one is `etsi-ts-103-701`.

```
$ python samples/iot-a/system.py --output coverage:etsi-ts-103-701
```

