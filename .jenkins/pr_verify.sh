#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

# The Jenkins job executing this script is maintained in the ONOS ci-management
# repo:
# https://gerrit.onosproject.org/plugins/gitiles/ci-management/+/refs/heads/master/jjb/templates/fabric-tna-jobs.yaml

# exit on errors
set -exu -o pipefail

SDE_BASE_DOCKER_IMG=opennetworking/bf-sde:9.2.0

echo "Build all profiles using SDE ${SDE_BASE_DOCKER_IMG}..."
make all SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-p4c

echo "Build and verify Java pipeconf"
make pipeconf MVN_FLAGS="-Pci-verify -Pcoverage"

echo "Upload coverage to codecov"
export CODECOV_TOKEN=75f36e70-2caf-46ab-9b76-7a1b9a419ebd
curl -s https://codecov.io/bash | bash

modified=$(git status --porcelain)
if [ -n "$modified" ]; then
  echo "The following build artifacts do not correspond to the expected ones,"
  echo "please run the build locally before pushing a new change, or add to .gitignore:"
  echo "$modified"
  exit 1
fi

# FIXME: add target to Makefile to build all profiles
echo "Run PTF tests for all profile"
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric-int
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric-spgw
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run fabric-spgw-int
