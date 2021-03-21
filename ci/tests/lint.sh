#!/bin/bash

set -e

source /home/venv/bin/activate
black --check --diff --color .
