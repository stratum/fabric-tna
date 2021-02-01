#!/bin/bash
# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FABRIC_TNA_ROOT="$( cd ${DIR}/.. && pwd )"
IMAGE="fabric-line-rate-test:0.0.1"
TEST_ARGS=()

mkdir -p "${DIR}/tmp"

while (( "$#" )); do
  case "$1" in
    # Override config parameters since we need to copy the actual config file
    # to the container.
    --trex-config | --p4info | --pipeline-config)
      cp -f "$2" "${DIR}/tmp/"
      TEST_ARGS+=("$1" "/tmp/$(basename "$2")")
      shift 2
      ;;
    *)
      TEST_ARGS+=("$1")
      shift 1
      ;;
  esac
done

docker run --rm \
           --rm -it --init \
           -v "${DIR}/src:/workspace/trex-scripts" \
           -v "${DIR}/tools:/workspace/tools" \
           -v "${DIR}/tmp:/tmp" \
           -v "${FABRIC_TNA_ROOT}/ptf/tests/ptf:/ptf" \
           -w /workspace \
           "${IMAGE}" "${TEST_ARGS[@]}"
