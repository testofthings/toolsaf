# Contributing to Toolsaf

This document will eventually describe how to contribute to Toolsaf.
On the mean time, please engagne the existing project contributors if you want to contribute!

## Unit Test
To run the unit tests, install _pytest_
```shell
pip install pytest
```
then:
```shell
pytest tests/
```

## Linting
To lint toolsaf code, install _pylint_
```shell
pip install pylint
```
then:
```shell
pylint toolsaf/
```
Samples and tests are not lint-compatible.

## Future plans
In the long run the framework is intended to support JSON-based security statement descripitons and to cover even more tools. Check the [roadmap](Roadmap.md) for upcoming features.
