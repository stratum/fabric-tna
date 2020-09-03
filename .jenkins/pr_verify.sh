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
make all SDE_DOCKER_IMG=${sdeBaseDockerImg}-p4c

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

# FIXME: add target to Makefile to build all profiles
echo "Run PTF tests for all profiles"
export STRATUM_BF_DOCKER_IMG=registry.aetherproject.org/tost/stratum-bfrt:${sdeVer}
export SDE_DOCKER_IMG=${sdeBaseDockerImg}-tm
./ptf/run/tm/run fabric
./ptf/run/tm/run fabric-int
./ptf/run/tm/run fabric-spgw
./ptf/run/tm/run fabric-spgw-int
