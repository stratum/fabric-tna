#!/bin/bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

MAVERICKS_CPU_PORT=320
MONTARA_CPU_PORT=192
SDE_DOCKER_IMG=${SDE_DOCKER_IMG:-opennetworking/bf-sde:9.2.0}

# DIR is this file directory.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "${DIR}/../" && pwd )"

P4_SRC_DIR=${ROOT_DIR}/p4src

set -e

PROFILE=$1
OTHER_PP_FLAGS=$2

# PWD is the directory where this script is called from (should be the root of
# this repo).
P4C_OUT=${ROOT_DIR}/tmp/${PROFILE}
# Prevent the creation by docker run to avoid having root owner
mkdir -p "${P4C_OUT}"

# Where the compiler output should be placed to be included in the pipeconf.
DEST_DIR=${ROOT_DIR}/src/main/resources/p4c-out/${PROFILE}


# If SDE_DOCKER_IMG env is set, use containerized version of the compiler
if [ -z "${SDE_DOCKER_IMG}" ]; then
  P4C_CMD="bf-p4c"
else
  P4C_CMD="docker run --rm -v ${P4C_OUT}:${P4C_OUT} -v ${P4_SRC_DIR}:${P4_SRC_DIR} -v ${DIR}:${DIR} -w ${DIR} ${SDE_DOCKER_IMG} bf-p4c"
fi

SDE_VER=$( ${P4C_CMD} --version | cut -d' ' -f2 )

# shellcheck disable=SC2086
function do_p4c() {
  pltf="$1_sde_${SDE_VER//./_}"
  cpu_port=$2
  echo "*** Compiling profile '${PROFILE}' for ${pltf} platform..."
  echo "*** Output in ${P4C_OUT}/${pltf}"
  p4c_flags="--auto-init-metadata"
  mkdir -p ${P4C_OUT}/${pltf}
  (
    $P4C_CMD --arch tna -g --create-graphs --verbose 2 \
      -o ${P4C_OUT}/${pltf} -I ${P4_SRC_DIR} \
      ${pp_flags} ${OTHER_PP_FLAGS} \
      ${p4c_flags} \
      --p4runtime-files ${P4C_OUT}/${pltf}/p4info.txt \
      --p4runtime-force-std-externs \
      ${DIR}/fabric_tna.p4
  )

  # Copy only the relevant files to the pipeconf resources.
  mkdir -p "${DEST_DIR}/stratum_bf/${pltf}/pipe"
  mkdir -p "${DEST_DIR}/stratum_bfrt/${pltf}/pipe"
  cp "${P4C_OUT}/${pltf}/p4info.txt" "${DEST_DIR}/stratum_bf/${pltf}"
  cp "${P4C_OUT}/${pltf}/bfrt.json" "${DEST_DIR}/stratum_bf/${pltf}"
  cp "${P4C_OUT}/${pltf}/fabric_tna.conf" "${DEST_DIR}/stratum_bf/${pltf}"
  cp "${P4C_OUT}/${pltf}/pipe/context.json" "${DEST_DIR}/stratum_bf/${pltf}/pipe"
  cp "${P4C_OUT}/${pltf}/pipe/tofino.bin" "${DEST_DIR}/stratum_bf/${pltf}/pipe"
  cp "${P4C_OUT}/${pltf}/pipe/context.json" "${DEST_DIR}/stratum_bfrt/${pltf}/pipe/"
  cp "${P4C_OUT}/${pltf}/pipe/tofino.bin" "${DEST_DIR}/stratum_bfrt/${pltf}/pipe/"
  echo "${cpu_port}" > "${DEST_DIR}/stratum_bf/${pltf}/cpu_port.txt"

  # New pipeline format which uses tar ball
  mkdir -p "${DEST_DIR}/stratum_bfrt/${pltf}"
  tar cf "pipeline.tar.bz2" -C "${DEST_DIR}/stratum_bf/${pltf}" .
  mv "pipeline.tar.bz2" "${DEST_DIR}/stratum_bfrt/${pltf}/"
  cp "${P4C_OUT}/${pltf}/p4info.txt" "${DEST_DIR}/stratum_bfrt/${pltf}/"
  echo "${cpu_port}" > "${DEST_DIR}/stratum_bfrt/${pltf}/cpu_port.txt"

  rm "${DEST_DIR}/stratum_bf/${pltf}/fabric_tna.conf"

  echo
}

do_p4c "montara" "${MONTARA_CPU_PORT}"
do_p4c "mavericks" "${MAVERICKS_CPU_PORT}"
