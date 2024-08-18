#!/usr/bin/env bash

WORKDIR=$(dirname -- "$0")

cd ${WORKDIR}/..
source .venv/bin/activate

python -m unittest discover test \
    && echo Root needed to run docker \
    && sudo test_installation/python37/test_python.sh \
    && sudo test_installation/python38/test_python.sh

if [ $? -eq 0 ]; then
    echo "Tests PASSED!!!"
else
    echo "Tests FAILED!!!"
fi