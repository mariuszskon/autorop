#!/bin/bash

set -e

LIBC_DATABASE_IMAGE="mariuszskon/libc-database:2021.06.23"

docker pull $LIBC_DATABASE_IMAGE

if [[ $1 == ubuntu:* || $1 == debian:* ]]
then
    docker build -f UbuntuDockerfile --build-arg "LIBC_DATABASE_IMAGE=$LIBC_DATABASE_IMAGE" --build-arg "UBUNTU_IMAGE=$1" -t "autorop-test-$1" ..
else
    echo "Unknown image '$1'"
    exit 1
fi
