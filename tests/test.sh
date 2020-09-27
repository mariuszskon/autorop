#!/bin/sh

black --check . &&
    mypy --strict --ignore-missing-imports . &&
    pytest -o 'python_functions=test_*' tests/
