#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FP4TEST_DIR=${DIR}/../../
PTF_DIR=${FP4TEST_DIR}/tests/ptf

err_report() {
    if [ "${TRAVIS}" = "true" ]; then
        # Dump all relevant logs to stdout to debug failing tests directly on
        # Travis CI
       echo
        echo "************************************************"
        echo "PTF LOG"
        echo "************************************************"
        cat "${PTF_DIR}"/ptf.log
    fi

    echo "************************************************"
    echo "GENERATION OF SOME TESTVECTORS FAILED :("
    echo "************************************************"
    exit 1
}

trap 'err_report' ERR
cd "${PTF_DIR}"

echo "************************************************"
echo "STARTING TESTVECTOR GENERATION FROM PTF TESTS..."
echo "************************************************"

# shellcheck disable=SC2068
make -f "${DIR}"/Makefile ${@}

echo "************************************************"
echo "GENERATED TESTVECTORS SUCCESSFULLY :)"
echo "************************************************"

