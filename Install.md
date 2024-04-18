# Installation

At the moment there is no _PyPi_ package, so you must pull sources manually.
Pull the sources outside of your security statement project, and then install TCSFE to the environment.
For example like this (assuming you are in your security statement project directory).

    $ mkdir ../external
    $ (cd ../external; git clone git@github.com:ouspg/tcsfw.git)
    $ pip install -e ../external/tcsfw

## Unit tests

If you want to run unit tests, you need to install _pytest_.
This is done in the TCFFW directory.

    $ pip install pytest

The tests in `tests/` can be run then as expected.

   $ pytest tests/

## Linting

Python code can be linted by _pylint_

    $ pip install pylint

Samples and tests are not lint-ready

    $ pylint tcsfw/






