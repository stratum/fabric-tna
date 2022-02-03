#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
FABRIC_TNA_ROOT="${DIR}"/../../..
PTF_FILTER=${PTF_FILTER:-}
TREX_PARAMS=${TREX_PARAMS:-}
PORT_MAP=${PORT_MAP:-}
PTF_DIR=${PTF_DIR:-}

mkdir -p "${FABRIC_TNA_ROOT}/ptf/run/hw/log"

# shellcheck source=.env
source "${FABRIC_TNA_ROOT}"/.env

fabricProfile=$1
if [ -z "${fabricProfile}" ]; then
    echo "fabric-tna profile is not set"
    exit 1
fi

if [ "${fabricProfile}" = "all" ]; then
    echo "Testing 'all' profiles is not supported on Tofino"
    exit 1
fi
echo "*** Testing profile '${fabricProfile}'..."

sdeVer_=$(echo "${SDE_VERSION}" | tr . _) # Replace dots with underscores
P4C_OUT=p4src/tna/build/${fabricProfile}/sde_${sdeVer_}
echo "*** Using P4 compiler output in ${P4C_OUT}..."

testerRunName=tester-${RANDOM}
function stop() {
    set +e
    echo "*** Stopping ${testerRunName}..."
    docker stop -t0 ${testerRunName} > /dev/null 2>&1
    docker cp ${testerRunName}:/tmp/. "${DIR}"/log > /dev/null 2>&1
    docker rm ${testerRunName} > /dev/null 2>&1
}
trap stop EXIT

echo "*** Starting ${testerRunName}..."
# Do not attach stdin if running in an environment without it (e.g., Jenkins)
it=$(test -t 0 && echo "-it" || echo "-t")
# shellcheck disable=SC2068
# mount localtime to container so test pcap time in name matches machine's local time
docker run --name "${testerRunName}" "${it}" \
    --network host \
    --privileged \
    -v "${FABRIC_TNA_ROOT}":/fabric-tna \
    -v /etc/localtime:/etc/localtime \
    -e P4C_OUT="${P4C_OUT}" \
    -e PTF_FILTER="${PTF_FILTER}" \
    -e SWITCH_ADDR="${SWITCH_ADDR}" \
    -e TREX_PARAMS="${TREX_PARAMS}" \
    -e PORT_MAP="${PORT_MAP}" \
    -e PTF_DIR="${PTF_DIR}" \
    --entrypoint /fabric-tna/ptf/run/hw/start_test.sh \
    "${TESTER_DOCKER_IMG}" \
    ${@}
