# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -eu -o pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
FP4TEST_ROOT="${DIR}"/../..
FABRIC_TNA="${FP4TEST_ROOT}"/..

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
testerRunName=tester-${randomNum}

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

# Run Tofino Model
# Replace dots with underscores to match pipeconf name
echo "*** Starting ${tmRunName} (from ${SDE_TM_DOCKER_IMG})..."
docker run --name ${tmRunName} -d -t --privileged \
    -v "${DIR}":/workdir -w /workdir \
    -v "${P4C_OUT}":/p4c-out \
    --entrypoint ./tm_entrypoint.sh \
    "${SDE_TM_DOCKER_IMG}"
sleep 5

# Run Stratum container
echo "*** Starting ${stratumBfRunName} (from ${STRATUM_DOCKER_IMG})..."
# shellcheck disable=SC2086
docker run --name ${stratumBfRunName} -d --privileged \
    --network "container:${tmRunName}" \
    -v "${DIR}":/workdir -w /workdir \
    --entrypoint ./stratum_entrypoint.sh \
    ${STRATUM_DOCKER_FLAG} \
    "${STRATUM_DOCKER_IMG}"
sleep 5
wait_for ${stratumBfRunName} 28000 600