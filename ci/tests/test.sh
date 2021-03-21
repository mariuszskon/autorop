#!/bin/bash

set -e

source /home/venv/bin/activate
export TERM=xterm  # hack to fix pwntools
coverage run --omit '/home/venv/*' -m pytest --reruns 2 &&
    coverage report
