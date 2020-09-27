#!/bin/sh

black --check --diff --color . &&
    mypy --strict --ignore-missing-imports . &&
    pytest -o 'python_functions=test_*' tests/
