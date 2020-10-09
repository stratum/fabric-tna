#!/bin/bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -eu -o pipefail

MAVERICKS_CPU_PORT=320 # quad-pipe
MONTARA_CPU_PORT=192 # dual-pipe

# DIR is this file directory.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
P4_SRC_DIR=${DIR}
ROOT_DIR="$( cd "${DIR}/../" && pwd )"

PROFILE=$1
OTHER_PP_FLAGS=$2

# shellcheck source=.env
source "${ROOT_DIR}/.env"

# PWD is the directory where this script is called from (should be the root of
# this repo).
P4C_OUT=${ROOT_DIR}/p4src/build/${PROFILE}
# Prevent the creation by docker run to avoid having root owner
mkdir -p "${P4C_OUT}"

# Where the compiler output should be placed to be included in the pipeconf.
DEST_DIR=${ROOT_DIR}/src/main/resources/p4c-out/${PROFILE}
# Where the pipeconf unit tests expect the compiler output should be placed.
TEST_DEST_DIR=${ROOT_DIR}/src/test/resources/p4c-out/${PROFILE}
DIRS=("${DEST_DIR}" "${TEST_DEST_DIR}")

P4C_CMD="docker run --rm -v ${P4C_OUT}:${P4C_OUT} -v ${P4_SRC_DIR}:${P4_SRC_DIR} -v ${DIR}:${DIR} -w ${DIR} ${SDE_P4C_DOCKER_IMG} bf-p4c"
SDE_VER=$( ${P4C_CMD} --version | cut -d' ' -f2 )

# shellcheck disable=SC2086
function base_build() {
  output_dir="${P4C_OUT}/sde_${SDE_VER//./_}"
  echo "*** Compiling profile '${PROFILE}'..."
  echo "*** Output in ${output_dir}"
  p4c_flags="--auto-init-metadata"
  mkdir -p ${output_dir}
  (
    time $P4C_CMD --arch tna -g --create-graphs --verbose 2 \
      -o ${output_dir} -I ${P4_SRC_DIR} \
      ${OTHER_PP_FLAGS} \
      ${p4c_flags} \
      --p4runtime-files ${output_dir}/p4info.txt \
      --p4runtime-force-std-externs \
      ${DIR}/fabric_tna.p4
  )

  # Generate the pipeline config binary
  docker run --rm -v "${output_dir}:${output_dir}" -w "${output_dir}" \
    ${PIPELINE_CONFIG_BUILDER_IMG} \
    -p4c_conf_file=./fabric_tna.conf \
    -bf_pipeline_config_binary_file=./pipeline_config.pb.bin
}

function gen_profile() {
  output_dir="${P4C_OUT}/sde_${SDE_VER//./_}"
  pltf="$1_sde_${SDE_VER//./_}"
  cpu_port=$2
  for d in "${DIRS[@]}"; do
    # Copy only the relevant files to the pipeconf resources.
    mkdir -p "${d}/${pltf}"
    cp "${output_dir}/p4info.txt" "${d}/${pltf}"
    echo "${cpu_port}" > "${d}/${pltf}/cpu_port.txt"
    cp "${output_dir}/pipeline_config.pb.bin" "${d}/${pltf}/"
    echo
  done
}

base_build
gen_profile "montara" "${MONTARA_CPU_PORT}"
gen_profile "mavericks" "${MAVERICKS_CPU_PORT}"
