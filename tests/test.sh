#!/bin/sh

black --check --diff --color . &&
    mypy --strict --ignore-missing-imports . &&
    pytest
