#!/bin/sh

black --check --diff --color . &&
    mypy . &&
    pytest
