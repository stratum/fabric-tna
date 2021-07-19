# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# 320 cpu port is for mavericks (65Q)

define run_tests
	python3 -u ptf_runner.py \
		--port-map $(PORT_MAP) \
		--ptf-dir $(PTF_DIR) \
		--cpu-port 320 --device-id 1 \
		--grpc-addr $(SWITCH_ADDR) \
		--p4info /p4c-out/p4info.txt \
		--tofino-pipeline-config /p4c-out/pipeline_config.pb.bin \
		$(TREX_PARAMS) \
		--profile $(1) \
		$(2)
endef

# Nothing to check
_checkenv:

include ../../tests/common/Makefile.profiles
