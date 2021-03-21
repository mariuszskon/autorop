#!/bin/bash

set -e

source /home/venv/bin/activate
uname -a
sysctl kernel.core_pattern
ldd --version | head -n 1
python --version
pip freeze
