#!/bin/bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -eu -o pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
FABRIC_TNA_ROOT="${DIR}"/../../..

randomNum=${RANDOM}

# shellcheck source=.env
source "${FABRIC_TNA_ROOT}"/.env

PTF_FILTER=${PTF_FILTER:-}
STRATUM_DOCKER_FLAG=${STRATUM_DOCKER_FLAG:-}

fabricProfile=$1
if [ -z "${fabricProfile}" ]; then
    echo "fabric profile is not set"
    exit 1
fi

echo "*** Testing profile '${fabricProfile}'..."

echo "Running for BMV2"
P4C_OUT=p4src/v1model/build/${fabricProfile}/bmv2
echo "*** Using P4 compiler output in ${P4C_OUT}..."

# Clean up old logs (if any)
rm -rf "${DIR}"/log
mkdir "${DIR}"/log

# stratum_bmv2
stratumBmv2ImageName=${STRATUM_BMV2_IMG}
stratumBmv2RunName=stratum-bmv2-${randomNum}

function stop_stratum_bmv2() {
    set +e
    echo "*** Stopping ${stratumBmv2ImageName}..."
    docker stop -t0 "${stratumBmv2RunName}" > /dev/null
}
trap stop_stratum_bmv2 EXIT


echo "*** Starting ${stratumBmv2RunName}..."
docker run --name ${stratumBmv2RunName} -d -it --rm --privileged \
-v "${FABRIC_TNA_ROOT}":/fabric-tna \
--entrypoint "/fabric-tna/ptf/run/bmv2/stratum_entrypoint.sh" \
"${stratumBmv2ImageName}"
sleep 2
