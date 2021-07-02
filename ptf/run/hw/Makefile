# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# 320 cpu port is for mavericks (65Q)

define run_tests
    python3 -u ptf_runner.py \
        --ptf-dir ../../tests/linerate --cpu-port 320 --device-id 1 \
        --port-map port_map.hw.json \
        --grpc-addr "10.128.13.29:9559" \
        --p4info /p4c-out/p4info.txt \
        --tofino-pipeline-config /p4c-out/pipeline_config.pb.bin \
        --trex-address "10.128.13.27" \
        --trex-config /fabric-tna/run/hw/trex-config/4-ports-with-l2.yaml \
        --profile $(1) \
        $(2)
endef

# Nothing to check
_checkenv:

include ../../tests/common/Makefile.profiles
