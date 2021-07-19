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
docker build -f ptf/Dockerfile -t "${TESTER_DOCKER_IMG}" .

# Jenkins uses 8 cores 15G VM
make -j8 all

echo "Build and verify Java pipeconf"
make constants pipeconf-ci MVN_FLAGS="-Pci-verify -Pcoverage"

echo "Upload coverage to codecov"
bash .jenkins/codecov.sh -Z

# Since the Java build is based on auto-generated P4InfoConstants.java (make
# constants above), check that checked-in file is up-to-date:
modified=$(git status --porcelain)
if [ -n "$modified" ]; then
  echo "The following build artifacts do not correspond to the expected ones,"
  echo "please run the build locally before pushing a new change:"
  echo "$modified"
  exit 1
fi

# We limit running PTF tests for only those profiles used in Aether, otherwise
# we exceed the 45 min limit on Jenkins.
# FIXME: revert once the PTF tests execution time is optimized (#238)
for profile in "fabric-int" "fabric-spgw-int"; do
# Run PTF tests for all profiles we just built
#for d in ./p4src/build/*/; do
#  profile=$(basename "${d}")

  echo "Run PTF tests for profile ${profile}"
  ./ptf/run/tm/run "${profile}"
  # Special case to test INT drop report with deflected packet.
  TM_DOD=1 ./ptf/run/tm/run "${profile}" TEST=int-dod

  echo "Verify TV generation for profile ${profile}"
  ./ptf/run/tv/run "${profile}"
  # Special case to test INT drop report with deflected packet.
  TM_DOD=1 ./ptf/run/tv/run "${profile}" TEST=int-dod

  rm -rf "logs/${profile}"
  mkdir -p "logs/${profile}"
  mv ptf/run/tm/log "logs/${profile}"
  mv ptf/tests/common/ptf.log "logs/${profile}/"
  mv ptf/tests/common/ptf.pcap "logs/${profile}/"
done
