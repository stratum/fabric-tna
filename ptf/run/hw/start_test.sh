#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
FABRIC_TNA_DIR=${DIR}/../..
PTF_DIR=${FABRIC_TNA_DIR}/tests/common

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
make -f "${DIR}"/Makefile ${@}

echo "************************************************"
echo "ALL PTF TESTS PASSED :)"
echo "************************************************"
