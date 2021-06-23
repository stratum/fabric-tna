#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
FABRIC_TNA_DIR=${DIR}/../..
PTF_DIR=${FABRIC_TNA_DIR}/tests/common
HW_DIR=${FABRIC_TNA_DIR}/run/hw

err_report() {
    echo "************************************************"
    echo "SOME PTF TESTS FAILED :("
    echo "************************************************"
    exit 1
}

trap 'err_report' ERR
cd "${PTF_DIR}"

echo "************************************************"
echo "STARTING PTF TESTS..."
echo "************************************************"

# shellcheck disable=SC2068
python3 -u ptf_runner.py --port-map port_map.veth.json \
		--ptf-dir linerate --cpu-port 320 --device-id 1 \
		--grpc-addr "127.0.0.1:28000" \
		--p4info /p4c-out/p4info.txt \
		--tofino-pipeline-config /p4c-out/pipeline_config.pb.bin \
        --trex-address "10.128.13.27" \
        --trex-config ${HW_DIR}/trex-config/trex-config-2ports.yaml \
        --skip-test True \
		--profile ${1} \
		${2}

echo "************************************************"
echo "ALL PTF TESTS PASSED :)"
echo "************************************************"
