#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

# The Jenkins job `fabric-tna-linerate-tests` executing this script is maintained in
# the ONOS ci-management repo:
# https://gerrit.onosproject.org/plugins/gitiles/ci-management/+/refs/heads/master/jjb/templates/fabric-tna-jobs.yaml
#
# This job should be executed nightly at 23:00 - 0:00 PST

# exit on errors
set -exu -o pipefail

source .env

echo "Build all profiles using SDE ${SDE_P4C_DOCKER_IMG}..."
# Pull first to avoid pulling multiple times in parallel by the make jobs
docker pull "${SDE_P4C_DOCKER_IMG}"
docker build -f ptf/Dockerfile -t "${TESTER_DOCKER_IMG}" .

make "${PROFILE}"

# PROFILE env variable set by Jenkins
echo "Run linerate tests for profile ${PROFILE}"
./ptf/run/hw/linerate "${PROFILE}"

rm -rf "logs/${PROFILE}"
mkdir -p "logs/${PROFILE}"
mv ptf/run/hw/log "logs/${PROFILE}"
mv ptf/tests/common/ptf.log "logs/${PROFILE}/"
mv ptf/tests/common/ptf.pcap "logs/${PROFILE}/"
