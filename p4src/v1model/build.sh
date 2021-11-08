#!/usr/bin/env bash
# shellcheck disable=SC2086
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -e

BMV2_CPU_PORT=255

BMV2_PP_FLAGS=""

PROFILE=$1
OTHER_PP_FLAGS=$2

# DIR is this file directory.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
P4_SRC_DIR=${DIR}/..
ROOT_DIR="$( cd "${DIR}/../.." && pwd )"
P4C_OUT=${ROOT_DIR}/p4src/v1model/build/${PROFILE}/bmv2
FABRIC_P4_FILE=${DIR}/fabric_v1model.p4

# Where the compiler output should be placed to be included in the pipeconf.
DEST_DIR=${ROOT_DIR}/src/main/resources/p4c-out/${PROFILE}

# shellcheck source=.env
source "${ROOT_DIR}/.env"

dockerRun="docker run --rm -w ${P4_SRC_DIR} -v ${P4_SRC_DIR}:${P4_SRC_DIR} -v ${P4C_OUT}:${P4C_OUT} ${P4C_DOCKER_IMG}"

echo "## Compiling profile ${PROFILE} in ${P4C_OUT}..."
echo "*** Output in ${P4C_OUT}"
mkdir -p ${P4C_OUT}

# Generate preprocessed P4 source (for debugging).
(
  ${dockerRun} p4c-bm2-ss --arch v1model \
  ${BMV2_PP_FLAGS} ${OTHER_PP_FLAGS} -I ${P4_SRC_DIR}\
  --pp ${P4C_OUT}/_pp.p4 ${FABRIC_P4_FILE}
)

# Generate BMv2 JSON and P4Info.
(
  ${dockerRun} p4c-bm2-ss --arch v1model -o ${P4C_OUT}/bmv2.json \
  ${BMV2_PP_FLAGS} ${OTHER_PP_FLAGS} -I ${P4_SRC_DIR}\
  --p4runtime-files ${P4C_OUT}/p4info.txt ${FABRIC_P4_FILE}
)

output_dir="${P4C_OUT}"
pltf="bmv2"

# Copy only the relevant files to the pipeconf resources.
mkdir -p "${DEST_DIR}/${pltf}"
cp "${output_dir}/p4info.txt" "${DEST_DIR}/${pltf}"
echo "${BMV2_CPU_PORT}" > "${DEST_DIR}/${pltf}/cpu_port.txt"
cp "${output_dir}/bmv2.json" "${DEST_DIR}/${pltf}/"
echo

# CPU port.
echo ${BMV2_CPU_PORT} > ${P4C_OUT}/cpu_port.txt
