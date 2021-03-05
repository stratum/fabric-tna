#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -ex

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

veth_setup.sh
dma_setup.sh

# Change workdir to a non-shared volume to improve container disk I/O
# performance, as tofino-model writes a lot of logs for each packet.
# Log files will be copied out of this container at the end of the test
# execution.
mkdir /tmp/workdir
cd /tmp/workdir
tofino-model --p4-target-config "${DIR}"/tm_conf.json --dod-test-mode
