# Contributing to Toolsaf

[Table of contents](README.md)

This document will eventually describe how to contribute to Toolsaf.
In the meantime, please contact Toolsaf team by mail <code>&#116;&#111;&#111;&#108;&#115;&#97;&#102;&#32;&#97;&#116;&#32;&#116;&#101;&#115;&#116;&#111;&#102;&#116;&#104;&#105;&#110;&#103;&#115;&#46;&#99;&#111;&#109;</code> if you want to contribute.

Before you start, please take a look at the [architecture documentation](architecture/README.md).
Then, in the toolsaf directory, install the development dependencies:
```shell
pip install -e .[dev]
```

## Unit Test
```shell
pytest tests/
```

## Linting

```shell
pylint toolsaf/
```

## Static Typing Check
```shell
mypy toolsaf/
```

Samples and tests are not lint/mypy-compatible.

## Releases

Every merge to `main` is released to [PyPI](https://pypi.org/project/toolsaf/) and [GitHub Releases](https://github.com/testofthings/toolsaf/releases).

The release workflow increments the patch version automatically. To start a new minor or major version, change `version=` in `VERSION` in the same pull request, e.g. `version=0.11.x`.

Each pull request description must have a `## Release notes` section. It becomes the release notes of the release.

## Future Plans

In the long run, the framework is intended to support JSON-based security statement descriptions and to cover even more tools. Check the [roadmap](Roadmap.md) for upcoming features.