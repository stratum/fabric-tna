#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
FP4TEST_DIR=${DIR}/../../
PTF_DIR=${FP4TEST_DIR}/tests/ptf

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

make -f "${DIR}"/Makefile "${@}"

echo "************************************************"
echo "ALL PTF TESTS PASSED :)"
echo "************************************************"
