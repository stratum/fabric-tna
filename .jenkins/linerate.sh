#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

# The Jenkins job `fabric-tna-linerate-tests` executing this script is maintained in
# the ONOS ci-management repo:
# https://gerrit.onosproject.org/plugins/gitiles/ci-management/+/refs/heads/master/jjb/templates/fabric-tna-jobs.yaml
#
# This job should be executed nightly at 23:00 - 0:00 PST

# exit on errors
set -exu -o pipefail

source .env

# PROFILE env variable set by Jenkins
echo "Run linerate tests for profile ${PROFILE}"
./ptf/run/hw/linerate "${PROFILE}"

rm -rf "logs/${PROFILE}"
mkdir -p "logs/${PROFILE}"
mv ptf/run/hw/log "logs/${PROFILE}"
mv ptf/tests/common/ptf.log "logs/${PROFILE}/"
mv ptf/tests/common/ptf.pcap "logs/${PROFILE}/"
