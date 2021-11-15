#!/usr/bin/env bash
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# jflint.sh - lint for Jenkins declarative pipeline jobs
#
# curl commands from: https://jenkins.io/doc/book/pipeline/development/#linter
set -e -u -o pipefail
JENKINS_URL=https://jenkins.onosproject.org/
JF_LIST=()
JF_FAIL=0
# if no args, and there's a Jenkinsfile in cwd, check it
if [ ! -n "$1" ] && [ -f "Jenkinsfile" ] ; then
  JF_LIST+=("Jenkinsfile")
else
# iterate over all args, check if they exist, then add to list of jenkinsfiles to check
  for arg in "$@"; do
    if [ -f "$arg" ]; then
      JF_LIST+=($arg)
    else
      echo "File does not exist: ${arg}"
      exit 1;
    fi
  done
fi
# JENKINS_CRUMB is needed if your Jenkins master has CRSF protection enabled as it should
JENKINS_CRUMB=$(curl -s "$JENKINS_URL/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")
for target in "${JF_LIST[@]-}"; do
  echo "Checking: '${target}'"
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