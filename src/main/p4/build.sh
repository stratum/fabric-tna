#!/bin/bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

MAVERICKS_CPU_PORT=320
MONTARA_CPU_PORT=192

# DIR is this file directory.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "${DIR}/../../../" && pwd )"

P4_SRC_DIR=${ROOT_DIR}/src/main/p4

set -e

PROFILE=$1
OTHER_PP_FLAGS=$2

# PWD is the directory where this script is called from (should be the root of
# this repo).
P4C_OUT=${PWD}/tmp/${PROFILE}

# Where the compiler output should be placed to be included in the pipeconf.
DEST_DIR=${DIR}/../resources/p4c-out/${PROFILE}/tofino


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
  pp_flags="-DCPU_PORT=${cpu_port}"
  p4c_flags="--auto-init-metadata"
  mkdir -p ${P4C_OUT}/${pltf}
  (
    set -x
    $P4C_CMD --arch tna -g --create-graphs --verbose 2 \
      -o ${P4C_OUT}/${pltf} -I ${P4_SRC_DIR} \
      ${pp_flags} ${OTHER_PP_FLAGS} \
      ${p4c_flags} \
      --p4runtime-files ${P4C_OUT}/${pltf}/p4info.txt \
      --p4runtime-force-std-externs \
      ${DIR}/fabric-tna.p4
  )

  # Copy only the relevant files to the pipeconf resources
  mkdir -p ${DEST_DIR}/${pltf}/pipe
  cp ${P4C_OUT}/${pltf}/p4info.txt ${DEST_DIR}/${pltf}
  cp ${P4C_OUT}/${pltf}/pipe/context.json ${DEST_DIR}/${pltf}/pipe
  cp ${P4C_OUT}/${pltf}/pipe/tofino.bin ${DEST_DIR}/${pltf}/pipe
  echo "${cpu_port}" > ${DEST_DIR}/${pltf}/cpu_port.txt

  echo
}

do_p4c "montara" ${MONTARA_CPU_PORT}
do_p4c "mavericks" ${MAVERICKS_CPU_PORT}

