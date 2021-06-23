# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# 320 cpu port is for mavericks (65Q)

define run_tests
	python3 -u ptf_runner.py --port-map port_map.veth.json \
		--ptf-dir ../../tests/unary --cpu-port 320 --device-id 1 \
		--grpc-addr "127.0.0.1:28000" \
		--p4info /p4c-out/p4info.txt \
		--tofino-pipeline-config /p4c-out/pipeline_config.pb.bin \
		--profile $(1) \
		$(2)
endef

# Nothing to check
_checkenv:

include ../../tests/common/Makefile.profiles
