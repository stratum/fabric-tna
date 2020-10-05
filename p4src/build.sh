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
  # TODO: remove the line below when compiler support register p4 info.
  P4INFO_PATCH_SHELL="sh -c"
else
  P4C_CMD="docker run --rm -v ${P4C_OUT}:${P4C_OUT} -v ${P4_SRC_DIR}:${P4_SRC_DIR} -v ${DIR}:${DIR} -w ${DIR} ${SDE_DOCKER_IMG} bf-p4c"
  # TODO: remove the line below when compiler support register p4 info.
  P4INFO_PATCH_SHELL="docker run --rm -v ${P4C_OUT}:${P4C_OUT} -v ${DIR}:${DIR} -w ${DIR} busybox sh -c"
fi

SDE_VER=$( ${P4C_CMD} --version | cut -d' ' -f2 )

# shellcheck disable=SC2086
function base_build() {
  pltf="sde_${SDE_VER//./_}"
  echo "*** Compiling profile '${PROFILE}' for ${pltf}..."
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
  # Adds register information to p4info file
  # TODO: remove this part when compiler support it.
  if [[ "$PROFILE" == *int ]]; then
    $P4INFO_PATCH_SHELL "cat ${DIR}/p4info-register.txt >> ${P4C_OUT}/${pltf}/p4info.txt"
  fi
}

# shellcheck disable=SC2086
function gen_profile() {
  output_dir="${P4C_OUT}/sde_${SDE_VER//./_}"
  pltf="$1_sde_${SDE_VER//./_}"
  cpu_port=$2

  # Copy only the relevant files to the pipeconf resources.
  mkdir -p "${DEST_DIR}/stratum_bf/${pltf}/pipe"
  mkdir -p "${DEST_DIR}/stratum_bfrt/${pltf}/pipe"
  cp "${output_dir}/p4info.txt" "${DEST_DIR}/stratum_bf/${pltf}"
  cp "${output_dir}/bfrt.json" "${DEST_DIR}/stratum_bf/${pltf}"
  cp "${output_dir}/fabric_tna.conf" "${DEST_DIR}/stratum_bf/${pltf}"
  cp "${output_dir}/pipe/context.json" "${DEST_DIR}/stratum_bf/${pltf}/pipe"
  cp "${output_dir}/pipe/tofino.bin" "${DEST_DIR}/stratum_bf/${pltf}/pipe"
  cp "${output_dir}/pipe/context.json" "${DEST_DIR}/stratum_bfrt/${pltf}/pipe/"
  cp "${output_dir}/pipe/tofino.bin" "${DEST_DIR}/stratum_bfrt/${pltf}/pipe/"
  echo "${cpu_port}" > "${DEST_DIR}/stratum_bf/${pltf}/cpu_port.txt"

  # New pipeline format which uses tar ball
  mkdir -p "${DEST_DIR}/stratum_bfrt/${pltf}"
  tar cf "pipeline.tar.bz2" -C "${DEST_DIR}/stratum_bf/${pltf}" .
  mv "pipeline.tar.bz2" "${DEST_DIR}/stratum_bfrt/${pltf}/"
  cp "${output_dir}/p4info.txt" "${DEST_DIR}/stratum_bfrt/${pltf}/"
  echo "${cpu_port}" > "${DEST_DIR}/stratum_bfrt/${pltf}/cpu_port.txt"

  rm "${DEST_DIR}/stratum_bf/${pltf}/fabric_tna.conf"

  echo
}

base_build
gen_profile "montara" "${MONTARA_CPU_PORT}"
gen_profile "mavericks" "${MAVERICKS_CPU_PORT}"
