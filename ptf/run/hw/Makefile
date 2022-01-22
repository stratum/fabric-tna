# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

define run_tests
    python3 -u ptf_runner.py \
        --port-map $(PORT_MAP) \
        --ptf-dir $(PTF_DIR) \
        --device-id 1 \
        --grpc-addr $(SWITCH_ADDR) \
        --p4info /fabric-tna/${P4C_OUT}/p4info.txt \
        --pipeline-config /fabric-tna/${P4C_OUT}/pipeline_config.pb.bin \
        $(TREX_PARAMS) \
        --profile $(1) \
        --xunit \
        --xunit-dir /tmp/ptf-logs \
        $(2)
endef

# Nothing to check
_checkenv:

include ../../tests/common/Makefile.profiles
