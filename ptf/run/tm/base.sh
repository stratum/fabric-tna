#!/bin/bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -eu -o pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
FABRIC_TNA_ROOT="${DIR}"/../..
FABRIC_TNA="${FABRIC_TNA_ROOT}"/..
TM_PORT_JSON=${TM_PORT_JSON:-""}
TM_DOD=${TM_DOD:=""}
JENKINS_URL=${JENKINS_URL:=""}

# shellcheck source=.env
source "${FABRIC_TNA}"/.env

PTF_FILTER=${PTF_FILTER:-}
STRATUM_DOCKER_FLAG=${STRATUM_DOCKER_FLAG:-}

fabricProfile=$1
if [ -z "${fabricProfile}" ]; then
    echo "fabric-tna profile is not set"
    exit 1
fi

if [ "${fabricProfile}" = "all" ]; then
    echo "Testing 'all' profiles is not supported on tofino-model"
    exit 1
fi
echo "*** Testing profile '${fabricProfile}'..."

detectedSdeVer=$(docker run --rm "${SDE_TM_DOCKER_IMG}" tofino-model --version | grep -oe '\([0-9]\+\.\)\+[0-9]\+')
echo "*** Detected BF SDE version ${detectedSdeVer} (tofino-model), required ${SDE_VERSION}..."
if [ "${detectedSdeVer}" != "${SDE_VERSION}" ]; then
    echo "ERROR: SDE version mismatch"
    exit 1
fi

# Find Tofino compiled artifacts
sdeVer_=$(echo "${SDE_VERSION}" | tr . _) # Replace dots with underscores
P4C_OUT=${FABRIC_TNA}/p4src/build/${fabricProfile}/sde_${sdeVer_}
echo "*** Using P4 compiler output in ${P4C_OUT}..."

# Fix a name for each container so we can stop them
randomNum=${RANDOM}
tmRunName=tofino-model-${randomNum}
stratumBfRunName=stratum-bf-${randomNum}

function stop() {
    set +e
    echo "*** Stopping ${stratumBfRunName}..."
    docker stop -t0 ${stratumBfRunName} > /dev/null 2>&1
    docker cp ${stratumBfRunName}:/tmp/workdir "${DIR}"/log/stratum-bf > /dev/null 2>&1
    docker rm ${stratumBfRunName} > /dev/null 2>&1

    echo "*** Stopping ${tmRunName}..."
    docker stop -t0 ${tmRunName} > /dev/null 2>&1
    docker cp ${tmRunName}:/tmp/workdir "${DIR}"/log/tofino-model > /dev/null 2>&1
    docker rm ${tmRunName} > /dev/null 2>&1
}
trap stop EXIT

function wait_for() {
    echo "*** Wait for ${1} to start up (port ${2})..."
    docker run --rm --network "container:${1}" toschneck/wait-for-it "localhost:${2}" -t "${3}"
}

rm -rf "${DIR}"/log
mkdir "${DIR}"/log

function run_command_in_docker_host() {
    # To run a command in the host that runs the Docker daemon.
    docker run -it --rm --privileged --pid=host alpine:3 \
        nsenter -t 1 -m -u -n -i bash -c "${1}"
}

# Initialize huge page if we are running on CI or macOS.
if [[ "${JENKINS_URL}" != "" ]] || [[ "${OSTYPE}" == "darwin"* ]]; then
    echo "*** Enabling huge page..."
    run_command_in_docker_host "echo 128 > /proc/sys/vm/nr_hugepages"
    run_command_in_docker_host "mkdir -p /dev/hugepages"
    run_command_in_docker_host "mount | grep hugetlbfs || mount -t hugetlbfs nodev /dev/hugepages"
fi

# Run Tofino Model
# Replace dots with underscores to match pipeconf name
echo "*** Starting ${tmRunName} (from ${SDE_TM_DOCKER_IMG})..."

OTHER_TM_DOCKER_ARGS=""
if [[ -n "${TM_PORT_JSON}" ]]; then
    # Fine the absolute path of the port map file and mount the file to the container
    # Also, pass the TM_PORT_JSON with the path to the container so the entrypoint
    # will start the Tofino model with port map file.
    JSON_PATH="$(cd "$(dirname "${TM_PORT_JSON}")" > /dev/null 2>&1 && pwd)"
    JSON_PATH="${JSON_PATH}/$(basename "${TM_PORT_JSON}")"
    OTHER_TM_DOCKER_ARGS="--mount src=${JSON_PATH},dst=${JSON_PATH},type=bind"
    OTHER_TM_DOCKER_ARGS="${OTHER_TM_DOCKER_ARGS} --env TM_PORT_JSON=${JSON_PATH}"
fi
if [[ -n "${TM_DOD}" ]]; then
    # Enable deflect on drop test
    OTHER_TM_DOCKER_ARGS="${OTHER_TM_DOCKER_ARGS} --env TM_DOD=${TM_DOD}"
fi

# shellcheck disable=SC2086
docker run --name ${tmRunName} -d -t --privileged \
    -v "${DIR}":/workdir -w /workdir \
    -v "${P4C_OUT}":/p4c-out \
    -v /dev/hugepages:/dev/hugepages \
    $OTHER_TM_DOCKER_ARGS \
    --entrypoint ./tm_entrypoint.sh \
    "${SDE_TM_DOCKER_IMG}"
sleep 5

# Run Stratum container
echo "*** Starting ${stratumBfRunName} (from ${STRATUM_DOCKER_IMG})..."
# shellcheck disable=SC2086
docker run --name ${stratumBfRunName} -d --privileged \
    --network "container:${tmRunName}" \
    -v "${DIR}":/workdir -w /workdir \
    -v /dev/hugepages:/dev/hugepages \
    --entrypoint ./stratum_entrypoint.sh \
    ${STRATUM_DOCKER_FLAG} \
    "${STRATUM_DOCKER_IMG}"
sleep 5
wait_for ${stratumBfRunName} 28000 600
