#!/bin/bash

source ./venv/bin/activate
black --check --diff --color .
