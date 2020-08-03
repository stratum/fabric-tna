# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0
PROFILES ?= all
ONOS_HOST ?= localhost

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
curr_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
curr_dir_sha := $(shell echo -n "$(curr_dir)" | shasum | cut -c1-7)

mvn_image := maven:3.6.1-jdk-11-slim
mvn_container := mvn-build-${curr_dir_sha}

onos_url := http://${ONOS_HOST}:8181/onos
onos_curl := curl --fail -sSL --user onos:rocks --noproxy localhost

pipeconf_app_name := org.stratumproject.fabric-tna
pipeconf_oar_file := $(shell ls -1 ${curr_dir}/target/fabric-tna-*.oar)

p4-build := ./p4src/build.sh

.PHONY: pipeconf

build: clean $(PROFILES) pipeconf

all: fabric fabric-spgw

fabric:
	@${p4-build} fabric ""

# Profiles which are not completed yet.
# fabric-simple:
# 	@${p4-build} fabric-simple "-DWITH_SIMPLE_NEXT"

# fabric-bng:
# 	@${p4-build} fabric-bng "-DWITH_BNG -DWITHOUT_XCONNECT"

# fabric-int:
# 	@${p4-build} fabric-int "-DWITH_INT_SOURCE -DWITH_INT_TRANSIT"

fabric-spgw:
	@${p4-build} fabric-spgw "-DWITH_SPGW"

# fabric-spgw-int:
# 	@${p4-build} fabric-spgw-int "-DWITH_SPGW -DWITH_INT_SOURCE -DWITH_INT_TRANSIT"

# Reuse the same container to persist mvn repo cache.
_create_mvn_container:
	@if ! docker container ls -a --format '{{.Names}}' | grep -q ${mvn_container} ; then \
		docker create -v ${curr_dir}:/mvn-src -w /mvn-src --name ${mvn_container} ${mvn_image} mvn clean package verify; \
	fi

_mvn_package:
	$(info *** Building ONOS app...)
	@mkdir -p target
	@docker start -a -i ${mvn_container}

pipeconf: _create_mvn_container _mvn_package
	$(info *** ONOS pipeconf .oar package created succesfully)
	@ls -1 ${curr_dir}/target/*.oar

pipeconf-install:
	$(info *** Installing and activating pipeconf app in ONOS at ${ONOS_HOST}...)
	${onos_curl} -X POST -HContent-Type:application/octet-stream \
		'${onos_url}/v1/applications?activate=true' \
		--data-binary @${pipeconf_oar_file}
	@echo

pipeconf-uninstall:
	$(info *** Uninstalling pipeconf app from ONOS (if present) at ${ONOS_HOST}...)
	-${onos_curl} -X DELETE ${onos_url}/v1/applications/${pipeconf_app_name}
	@echo

netcfg:
	$(info *** Pushing tofino-netcfg.json to ONOS at ${ONOS_HOST}...)
	${onos_curl} -X POST -H 'Content-Type:application/json' \
		${onos_url}/v1/network/configuration -d@./tofino-netcfg.json
	@echo

clean:
	-rm -rf src/main/resources/p4c-out

deep-clean: clean
	-rm -rf tmp
	-rm -rf target
	-docker rm ${mvn_container} > /dev/null 2>&1
