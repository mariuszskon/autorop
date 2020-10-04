#!/bin/sh

black --check --diff --color . &&
    mypy -p autorop &&
    coverage run -m pytest --reruns 3 &&
    coverage report
