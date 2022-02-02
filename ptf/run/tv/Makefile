# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

PORTMAP ?= /fabric-tna/ptf/run/tm/port_map.veth.json
GRPCADDR ?= 127.0.0.1:28000
CPUPORT ?= 320

define run_tests
	python3 -u ptf_runner.py --port-map $(PORTMAP) \
		--ptf-dir ../../tests/unary --cpu-port $(CPUPORT) --device-id 1 \
		--grpc-addr $(GRPCADDR) \
		--p4info /fabric-tna/${P4C_OUT}/p4info.txt \
		--pipeline-config /fabric-tna/${P4C_OUT}/pipeline_config.pb.bin \
		--generate-tv \
		--loopback \
		--profile $(1) \
		$(2)
endef

.DEFAULT_GOAL := all

#Nothing to check
_checkenv:

include ../../tests/common/Makefile.profiles
