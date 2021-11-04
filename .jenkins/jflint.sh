#!/usr/bin/env bash
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

# jflint.sh - lint for Jenkins declarative pipeline jobs
#
# curl commands from: https://jenkins.io/doc/book/pipeline/development/#linter

set -e -u -o pipefail

JENKINS_URL=https://jenkins.onosproject.org/
JF_LIST=()

JF_FAIL=0

# if no args, and there's a Jenkinsfile in cwd, check it
if [ -z "$1" ] && [ -f "Jenkinsfile" ] ; then
  JF_LIST+=("Jenkinsfile")
else
# iterate over all args, check if they exist, then add to list of jenkinsfiles to check
  for arg in "$@"; do
    if [ -f "$arg" ]; then
      JF_LIST+=("$arg")
    else
      echo "File does not exist: ${arg}"
      exit 1;
    fi
  done
fi

# JENKINS_CRUMB is needed if your Jenkins master has CRSF protection enabled as it should
JENKINS_CRUMB=$(curl -s "$JENKINS_URL/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")

for target in "${JF_LIST[@]-}"; do
  echo "Checking: '${target}' (against ${JENKINS_URL})"
  CURL_OUT=$(curl -s -H "${JENKINS_CRUMB}" -F "jenkinsfile=<${target}" $JENKINS_URL/pipeline-model-converter/validate)

  # Jenkins doesn't set a HTTP failure code when validation fails, so check output
  if [[ $CURL_OUT =~ Jenkinsfile\ successfully\ validated ]]
  then
    echo "Validated successfully: '${target}'"
  else
    echo "Failed to validate: '${target}' - errors:"
    echo "$CURL_OUT"
    JF_FAIL=1
  fi

done

exit $JF_FAIL
