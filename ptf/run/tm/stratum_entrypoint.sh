#!/bin/bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -ex

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
STRATUM_ARGS=("$@")

mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Change workdir to a non-shared volume to improve container disk I/O
# performance, as bf_drivers writes many logs during tests execution.
# Log files will be copied out of this container once stopped (see run.)
mkdir /tmp/workdir
cd /tmp/workdir

stratumBin=/usr/bin/stratum_bf
if test -f "/usr/bin/stratum_bfrt"; then
    stratumBin="/usr/bin/stratum_bfrt \
      -bfrt_table_sync_timeout_ms 10000"
fi

${stratumBin} \
    -bf_sde_install=/usr \
    -bf_switchd_background=true \
    -bf_switchd_cfg=/usr/share/stratum/tofino_skip_p4_no_bsp.conf \
    -chassis_config_file="${DIR}"/chassis_config.pb.txt \
    -external_stratum_urls=0.0.0.0:28000 \
    -forwarding_pipeline_configs_file=/dev/null \
    -log_dir=./ \
    -logtostderr=true \
    -stderrthreshold=0 \
    -v=0 \
    -persistent_config_dir=/tmp \
    -write_req_log_file=./p4rt-write-reqs.log \
    -enable_onlp=false \
    "${STRATUM_ARGS[@]}" \
    > ./stratum_bf.log 2>&1
