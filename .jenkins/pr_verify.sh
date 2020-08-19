#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

# exit on errors
set -exu -o pipefail

SDE_BASE_DOCKER_IMG=SDE_DOCKER_IMG=opennetworking/bf-sde:9.2.0

echo "Build all profiles using SDE ${SDE_BASE_DOCKER_IMG}..."
make all SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-p4c

echo "Build and verify Java pipeconf"
make pipeconf MVN_FLAGS="-Pci-verify -Pcoverage"

echo "Upload coverage to codecov"
bash <(curl -s https://codecov.io/bash)

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
SDE_DOCKER_IMG=${SDE_BASE_DOCKER_IMG}-tm ./ptf/run/tm/run
fabric-spgw-int
