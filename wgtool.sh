#!/usr/bin/env bash

set -e
cd $(dirname -- "$0")
source .venv/bin/activate 2> /dev/null
python ./src/wgtool/cli.py "$@"
deactivate
