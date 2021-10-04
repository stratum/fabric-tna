#!/usr/bin/env bash
# shellcheck disable=SC2086
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -e

BMV2_CPU_PORT=255

# -D defines the macro used within the P4 files (e.g. -DTARGET_BMV2 will be used as `#ifdef TARGET_BMV2`)
BMV2_PP_FLAGS="-DTARGET_BMV2 -DCPU_PORT=${BMV2_CPU_PORT} -DWITH_PORT_COUNTER -DWITH_DEBUG"

PROFILE=$1
OTHER_PP_FLAGS=$2

# DIR is this file directory.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
P4_SRC_DIR=${DIR}/..
ROOT_DIR="$( cd "${DIR}/../.." && pwd )"
OUT_DIR=${DIR}/build/${PROFILE}/bmv2
FABRIC_P4_FILE=${DIR}/fabric_v1model.p4

# shellcheck source=.env
source "${ROOT_DIR}/.env"


mkdir -p ${OUT_DIR}
mkdir -p ${OUT_DIR}/graphs

echo
echo "## Compiling profile ${PROFILE} in ${OUT_DIR}..."

dockerRun="docker run --rm -w ${P4_SRC_DIR} -v ${P4_SRC_DIR}:${P4_SRC_DIR} -v ${OUT_DIR}:${OUT_DIR} ${P4C_DOCKER_IMG}"

# Generate preprocessed P4 source (for debugging).
(set -x; ${dockerRun} p4c-bm2-ss --arch v1model \
        ${BMV2_PP_FLAGS} ${OTHER_PP_FLAGS} -I ${P4_SRC_DIR}\
        --pp ${OUT_DIR}/_pp.p4 ${FABRIC_P4_FILE})

# Generate BMv2 JSON and P4Info.
(set -x; ${dockerRun} p4c-bm2-ss --arch v1model -o ${OUT_DIR}/bmv2.json \
        ${BMV2_PP_FLAGS} ${OTHER_PP_FLAGS} -I ${P4_SRC_DIR}\
        --p4runtime-files ${OUT_DIR}/p4info.txt ${FABRIC_P4_FILE})

# CPU port.
(set -x; echo ${BMV2_CPU_PORT} > ${OUT_DIR}/cpu_port.txt)
