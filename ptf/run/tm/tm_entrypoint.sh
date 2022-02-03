#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

set -ex

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
TM_ARGS=""

veth_setup.sh
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Change workdir to a non-shared volume to improve container disk I/O
# performance, as tofino-model writes a lot of logs for each packet.
# Log files will be copied out of this container at the end of the test
# execution.
mkdir /tmp/workdir
cd /tmp/workdir

if [[ -n "${TM_PORT_JSON}" ]]; then
  TM_ARGS="-f ${TM_PORT_JSON}"
fi
if [[ -n "${TM_DOD}" ]]; then
  TM_ARGS="${TM_ARGS} --dod-test-mode"
fi

# shellcheck disable=SC2086
tofino-model --p4-target-config "${DIR}"/tm_conf.json $TM_ARGS
