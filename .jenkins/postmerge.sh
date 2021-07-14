#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

# The Jenkins job `fabric-tna-postmerge` executing this script is maintained in
# the ONOS ci-management repo:
# https://gerrit.onosproject.org/plugins/gitiles/ci-management/+/refs/heads/master/jjb/templates/fabric-tna-jobs.yaml
#
# This job should be executed for each commit to master.

# exit on errors
set -exu -o pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Make sure master is not broken by executing the same verify steps for pull
# requests.
bash "${DIR}"/pr_verify.sh

source .env
docker push "${TESTER_DOCKER_IMG}"
