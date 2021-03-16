#!/bin/bash

source ./venv/bin/activate
export TERM=xterm  # hack to fix pwntools
coverage run -m pytest --reruns 5 &&
    coverage report
