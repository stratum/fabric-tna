# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

PORTMAP ?= port_map.veth.json
GRPCADDR ?= 127.0.0.1:28000
CPUPORT ?= 320

define run_tests
	python -u ptf_runner.py --port-map $(PORTMAP) \
		--ptf-dir fabric.ptf --cpu-port $(CPUPORT) --device-id 1 \
		--grpc-addr $(GRPCADDR) \
		--p4info /p4c-out/p4info.txt \
		--tofino-pipeline-config /p4c-out/pipeline_config.pb.bin \
		--generate-tv \
		--loopback \
		$(2)
endef

.DEFAULT_GOAL := all

#Nothing to check
_checkenv:

include ../../tests/ptf/Makefile.profiles
