#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TESTS_DIR=${DIR}/../../tests

err_report() {
    echo "************************************************"
    echo "GENERATION OF SOME TESTVECTORS FAILED :("
    echo "************************************************"
    exit 1
}

trap 'err_report' ERR
cd "${TESTS_DIR}"

echo "************************************************"
echo "STARTING TESTVECTOR GENERATION FROM PTF TESTS..."
echo "************************************************"

# shellcheck disable=SC2068
make -f "${DIR}"/Makefile ${@}

echo "************************************************"
echo "GENERATED TESTVECTORS SUCCESSFULLY :)"
echo "************************************************"

