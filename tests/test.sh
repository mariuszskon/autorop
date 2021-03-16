#!/bin/bash

cd ci/
./build.sh $1 &&
    docker run --rm "autorop-test-$1" ./versions.sh &&
    docker run --rm "autorop-test-$1" ./lint.sh &&
    docker run --rm "autorop-test-$1" ./typecheck.sh &&
    docker run --rm "autorop-test-$1" ./test.sh
