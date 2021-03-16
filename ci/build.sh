#!/bin/bash

set -e

docker build -f LibcdbDockerfile -t "autorop-libcdb-builder" ..

if [[ $1 == ubuntu:* || $1 == debian:* ]]
then
    docker build -f UbuntuDockerfile --build-arg "UBUNTU_IMAGE=$1" -t "autorop-test-$1" ..
else
    echo "Unknown image '$1'"
    exit 1
fi
