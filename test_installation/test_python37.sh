#!/usr/bin/env bash

WORKDIR=$(dirname -- "$0")

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root"
    exit 1
fi

service docker start
sleep 2
docker build -f ${WORKDIR}/Dockerfile.python37 -t wgtool ${WORKDIR}/..
docker run -it wgtool show
