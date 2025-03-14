# Contributing to Toolsaf

[Table of contents](README.md)

This document will eventually describe how to contribute to Toolsaf.
In the meantime, please contact Toolsaf team by mail <code>&#116;&#111;&#111;&#108;&#115;&#97;&#102;&#32;&#97;&#116;&#32;&#116;&#101;&#115;&#116;&#111;&#102;&#116;&#104;&#105;&#110;&#103;&#115;&#46;&#99;&#111;&#109;</code> if you want to contribute.

Before you start, please take a look at the [architecture documentation](architecture/README.md).

## Unit Test
To run the unit tests, install _pytest_:
```shell
pip install pytest
```
Then:
```shell
pytest tests/
```

## Linting
To lint the Toolsaf code, install _pylint_:
```shell
pip install pylint
```
Then:
```shell
pylint toolsaf/
```

## Static Typing Check
To perform a typing check, install _mypy_:
```shell
pip install mypy
```
Then:
```shell
mypy toolsaf/
```

Samples and tests are not lint/mypy-compatible.

## Future Plans

In the long run, the framework is intended to support JSON-based security statement descriptions and to cover even more tools. Check the [roadmap](Roadmap.md) for upcoming features.