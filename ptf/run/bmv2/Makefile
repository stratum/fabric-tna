#!/bin/bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

define run_tests
	python3 -u ptf_runner.py \
	--platform bmv2 \
	--port-map /fabric-tna/ptf/run/bmv2/port_map.veth.json \
	--ptf-dir ../../tests/unary \
	--cpu-port 255 --device-id 1 \
	--grpc-addr 127.0.0.1:28000 \
	--p4info /fabric-tna/"${P4C_OUT}"/p4info.txt \
	--pipeline-config /fabric-tna/"${P4C_OUT}"/bmv2.json \
	--profile $(1) \
	$(2)
endef

.DEFAULT_GOAL := all

#Nothing to check
_checkenv:

include ../../tests/common/Makefile.profiles

