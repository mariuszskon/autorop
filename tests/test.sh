#!/bin/sh

black --check --diff --color . &&
    mypy -m autorop &&
    pytest
