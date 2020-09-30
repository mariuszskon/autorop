#!/bin/sh

black --check --diff --color . &&
    mypy -p autorop &&
    pytest
