#!/usr/bin/env bash
# shellcheck disable=SC2086
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -e

BMV2_CPU_PORT="255"
BMV2_PP_FLAGS="-DTARGET_BMV2 -DCPU_PORT=${BMV2_CPU_PORT} -DWITH_PORT_COUNTER -DWITH_DEBUG"
FABRIC_P4_FILE=fabric_v1model.p4

PROFILE=$1
OTHER_PP_FLAGS=$2

SRC_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
OUT_DIR=${SRC_DIR}/build/${PROFILE}/bmv2


mkdir -p ${OUT_DIR}
mkdir -p ${OUT_DIR}/graphs

echo
echo "## Compiling profile ${PROFILE} in ${OUT_DIR}..."

dockerImage=opennetworking/p4c:stable-20210108
dockerRun="docker run --rm -w ${SRC_DIR} -v ${SRC_DIR}:${SRC_DIR} -v ${OUT_DIR}:${OUT_DIR} ${dockerImage}"

# Generate preprocessed P4 source (for debugging).
(set -x; ${dockerRun} p4c-bm2-ss --arch v1model \
        ${BMV2_PP_FLAGS} ${OTHER_PP_FLAGS} \
        --pp ${OUT_DIR}/_pp.p4 ${FABRIC_P4_FILE})

# Generate BMv2 JSON and P4Info.
(set -x; ${dockerRun} p4c-bm2-ss --arch v1model -o ${OUT_DIR}/bmv2.json \
        ${BMV2_PP_FLAGS} ${OTHER_PP_FLAGS} \
        --p4runtime-files ${OUT_DIR}/p4info.txt ${FABRIC_P4_FILE})

# CPU port.
(set -x; echo ${BMV2_CPU_PORT} > ${OUT_DIR}/cpu_port.txt)
