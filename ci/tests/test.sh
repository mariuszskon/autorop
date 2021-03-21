#!/bin/bash

set -e

source ./venv/bin/activate
export TERM=xterm  # hack to fix pwntools
coverage run -m pytest --reruns 2 &&
    coverage report
