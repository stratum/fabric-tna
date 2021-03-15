#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

# The Jenkins job `fabric-tna-pr-verify` executing this script is maintained in
# the ONOS ci-management repo:
# https://gerrit.onosproject.org/plugins/gitiles/ci-management/+/refs/heads/master/jjb/templates/fabric-tna-jobs.yaml
#
# This job should be executed for each pull request.

# TODO (carmelo): consider using a declarative Jenkins pipeline so we
# can parallelize some of the tasks.

# exit on errors
set -exu -o pipefail

source .env

echo "Build all profiles using SDE ${SDE_P4C_DOCKER_IMG}..."
# Pull first to avoid pulling multiple times in parallel by the make jobs
docker pull "${SDE_P4C_DOCKER_IMG}"
# Jenkins uses 8 cores 15G VM
make -j8 all

# Run PTF tests for all profiles we just built
for d in ./p4src/build/*/; do
  profile=$(basename "${d}")

  echo "Run PTF tests for profile ${profile}"
  ./ptf/run/tm/run "${profile}"

  echo "Verify TV generation for profile ${profile}"
  ./ptf/run/tv/run "${profile}"

  rm -rf "logs/${profile}"
  mkdir -p "logs/${profile}"
  mv ptf/run/tm/log "logs/${profile}"
  mv ptf/tests/ptf/ptf.log "logs/${profile}/"
  mv ptf/tests/ptf/ptf.pcap "logs/${profile}/"
done
