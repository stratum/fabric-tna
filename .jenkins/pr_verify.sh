#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

# The Jenkins job `fabric-tna-pr-verify` executing this script is maintained in
# the ONOS ci-management repo:
# https://gerrit.onosproject.org/plugins/gitiles/ci-management/+/refs/heads/master/jjb/templates/fabric-tna-jobs.yaml
#
# This job should be executed for each pull request.

# TODO (carmelo): consider using a declarative Jenkins pipeline definition so we
# can parallelize some of the tasks.

# exit on errors
set -exu -o pipefail

sdeVer="9.2.0"
sdeBaseDockerImg=opennetworking/bf-sde:${sdeVer}

echo "Build all profiles using SDE ${sdeBaseDockerImg}..."
# Pull first to avoid pulling multiple times in parallel by the make jobs
docker pull ${sdeBaseDockerImg}-p4c
# Jenkins uses 8 cores 15G VM
make -j8 all SDE_DOCKER_IMG=${sdeBaseDockerImg}-p4c

echo "Build and verify Java pipeconf"
make constants pipeconf MVN_FLAGS="-Pci-verify -Pcoverage"

echo "Upload coverage to codecov"
export CODECOV_TOKEN=75f36e70-2caf-46ab-9b76-7a1b9a419ebd
curl -s https://codecov.io/bash | bash

# Since the Java build is based on auto-generated P4InfoConstants.java (make
# constants above), check that checked-in file is up-to-date:
modified=$(git status --porcelain)
if [ -n "$modified" ]; then
  echo "The following build artifacts do not correspond to the expected ones,"
  echo "please run the build locally before pushing a new change:"
  echo "$modified"
  exit 1
fi

# Run PTF tests for all profiles we just built
export STRATUM_BF_DOCKER_IMG=registry.aetherproject.org/tost/stratum-bfrt:${sdeVer}
export SDE_DOCKER_IMG=${sdeBaseDockerImg}-tm
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
