#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
PTF_ROOT=${DIR}/../..
TEST_DIR=${PTF_ROOT}/tests/common

err_report() {
    echo "************************************************"
    echo "SOME PTF TESTS FAILED :("
    echo "************************************************"
    exit 1
}

trap 'err_report' ERR
cd "${TEST_DIR}"

echo "************************************************"
echo "STARTING PTF TESTS..."
echo "************************************************"

# shellcheck disable=SC2068
make -f "${DIR}"/Makefile ${@}

echo "************************************************"
echo "ALL PTF TESTS PASSED :)"
echo "************************************************"
