#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

# The Jenkins job `fabric-tna-pr-verify` executing this script is maintained in
# the ONOS ci-management repo:
# https://gerrit.onosproject.org/plugins/gitiles/ci-management/+/refs/heads/master/jjb/templates/fabric-tna-jobs.yaml
#
# This job should be executed for each pull request.

# TODO (carmelo): consider using a declarative Jenkins pipeline definition so we
# can parallelize some of the tasks.

# exit on errors
set -exu -o pipefail

SDE_BASE_DOCKER_IMG=opennetworking/bf-sde:9.2.0

echo "Build all profiles using SDE ${SDE_BASE_DOCKER_IMG}..."
make all SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-p4c

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
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric-int
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric-spgw
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric-spgw-int
