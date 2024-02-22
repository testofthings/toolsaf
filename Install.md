# Installation

The following outlines installation of this Python software.

## Clone the project

Clone the project from _Github_ and move to its root directory.

```
$ git clone git://git@github.com/ouspg/tcsfw.git
...
$ cd tcsfw
```

## Create virtual environement

Create _venv_ virtual environement and activate it. 

```
$ python3 -m venv create .venv
...
$ source .venv/bin/activate
```

## Install

Install the requirements

```
$ pip install -r requirements.txt
```
To make sure the code runs easily from command line, install also the software itself.
```
$ pip install -e .
```

## Installation is ready

The installation is now ready. You can test e.g. by printing out command-line help.

```
$ python tcsfw/main.py --help
```

## Run unit tests

If you want to run unit tests, you need to install _pytest_.

```
$ pip install pytest
```

The tests in `tests/` can be run then as expected.

```
$ pytest tests/
```








