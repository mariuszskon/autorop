#!/bin/bash

set -e

source /home/venv/bin/activate
mypy -p autorop
