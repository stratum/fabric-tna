# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# 320 cpu port is for mavericks (65Q)

DEVICE ?= stratum-bf

DEVICE_CONFIG_BF := --tofino-bin /p4c-out/pipe/tofino.bin --tofino-ctx-json /p4c-out/pipe/context.json
DEVICE_CONFIG_BFRT := --tofino-pipeline-tar /p4c-out/pipeline.tar.bz2

ifeq ($(DEVICE),stratum-bfrt)
config := $(DEVICE_CONFIG_BFRT)
else
config := $(DEVICE_CONFIG_BF)
endif

define run_tests
	python -u ptf_runner.py --device $(DEVICE) --port-map port_map.veth.json \
		--ptf-dir fabric.ptf --cpu-port 320 --device-id 1 \
		--grpc-addr "127.0.0.1:28000" \
		--p4info /p4c-out/p4info.txt \
		$(config) \
		$(2)
endef

# Nothing to check
_checkenv:

include ../../tests/ptf/Makefile.profiles
