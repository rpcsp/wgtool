#!/usr/bin/env bash

source .venv/bin/activate

python -m unittest discover test \
    && echo Root needed to run docker \
    && sudo test_installation/test_python37.sh \
    && sudo test_installation/test_python38.sh

if [ $? -eq 0 ]; then
    echo "Tests PASSED!!!"
else
    echo "Tests FAILED!!!"
fi