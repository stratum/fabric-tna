# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

define run_tests
	python3 -u ptf_runner.py \
		--port-map /fabric-tna/ptf/run/tm/port_map.veth.json \
		--ptf-dir ../../tests/unary --device-id 1 \
		--grpc-addr "127.0.0.1:28000" \
		--p4info /fabric-tna/${P4C_OUT}/p4info.txt \
		--pipeline-config /fabric-tna/${P4C_OUT}/pipeline_config.pb.bin \
		--profile $(1) \
		$(2)
endef

# Nothing to check
_checkenv:

include ../../tests/common/Makefile.profiles
