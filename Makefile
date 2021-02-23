# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

# Absolute directory of this Makefile
DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
DIR_SHA := $(shell echo -n "$(DIR)" | shasum | cut -c1-7)

# .env cannot be included as-is as some variables are defined with ${A:-B}
# notation to allow overrides. Resolve overrides in a temp file and include that.
RESOLVED_ENV := /tmp/fabric-tna.$(DIR_SHA).env
IGNORE := $(shell bash -c 'eval "source $(DIR)/.env && echo \"$$(cat $(DIR)/.env)\""' > $(RESOLVED_ENV))
include $(RESOLVED_ENV)

# Replace dots with underscores
SDE_VER_ := $(shell echo $(SDE_VERSION) | tr . _)

# By default use docker volume for the mvn artifacts cache, but allow passing a
# local ~/.m2 directory using the MVN_CACHE env.
MVN_CACHE_DOCKER_VOLUME := mvn-cache-$(DIR_SHA)
MVN_CACHE ?= $(MVN_CACHE_DOCKER_VOLUME)
MVN_FLAGS ?=

ONOS_HOST ?= localhost
ONOS_URL := http://$(ONOS_HOST):8181/onos
ONOS_CURL := curl --fail -sSL --user onos:rocks --noproxy localhost

PIPECONF_APP_NAME := org.stratumproject.fabric-tna
PIPECONF_OAR_FILE := $(DIR)/target/fabric-tna-1.0.0-SNAPSHOT.oar

# Profiles to build by default (all)
PROFILES ?= fabric fabric-spgw fabric-int fabric-spgw-int

build: clean $(PROFILES) pipeconf

all: $(PROFILES)

fabric:
	@$(DIR)/p4src/build.sh fabric ""

# Profiles which are not completed yet.
# fabric-simple:
# 	@$(DIR)/p4src/build.sh fabric-simple "-DWITH_SIMPLE_NEXT"

# fabric-bng:
# 	@$(DIR)/p4src/build.sh fabric-bng "-DWITH_BNG -DWITHOUT_XCONNECT"

fabric-int:
	@$(DIR)/p4src/build.sh fabric-int "-DWITH_INT"

fabric-spgw:
	@$(DIR)/p4src/build.sh fabric-spgw "-DWITH_SPGW"

fabric-spgw-int:
	@$(DIR)/p4src/build.sh fabric-spgw-int "-DWITH_SPGW -DWITH_INT"

constants:
	docker run -v $(DIR):$(DIR) -w $(DIR) --rm \
		--entrypoint ./util/gen-p4-constants.py $(TESTER_DOCKER_IMG) \
		-o $(DIR)/src/main/java/org/stratumproject/fabric/tna/behaviour/P4InfoConstants.java \
		p4info $(DIR)/p4src/build/fabric-spgw-int/sde_$(SDE_VER_)/p4info.txt

_mvn_package:
	$(info *** Building ONOS app...)
	@mkdir -p target
	docker run --rm -v $(DIR):/mvn-src -w /mvn-src \
		-v $(MVN_CACHE):/root/.m2 $(MAVEN_DOCKER_IMAGE) mvn $(MVN_FLAGS) clean package

pipeconf: _mvn_package
	$(info *** ONOS pipeconf .oar package created succesfully)
	@ls -1 $(DIR)/target/*.oar

pipeconf-test: _mvn_package
	$(info *** Testing ONOS pipeconf)
	docker run --rm -v $(DIR):mvn-src -w /mvn-src \
		-v $(MVN_CACHE):/root/.m2 $(MAVEN_DOCKER_IMAGE) mvn test

_pipeconf-oar-exists:
	@test -f $(PIPECONF_OAR_FILE) || (echo "pipeconf .oar not found" && exit 1)

pipeconf-install: _pipeconf-oar-exists
	$(info *** Installing and activating pipeconf app in ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/octet-stream \
		$(ONOS_URL)/v1/applications?activate=true \
		--data-binary @$(PIPECONF_OAR_FILE)
	@echo

pipeconf-uninstall:
	$(info *** Uninstalling pipeconf app from ONOS at $(ONOS_HOST)...)
	-$(ONOS_CURL) -X DELETE $(ONOS_URL)/v1/applications/$(PIPECONF_APP_NAME)
	@echo

netcfg:
	$(info *** Pushing tofino-netcfg.json to ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/json \
		$(ONOS_URL)/v1/network/configuration -d@./tofino-netcfg.json
	@echo

#FIXME: p4i no longer starts with SDE 9.3.1
p4i:
	$(info *** Started p4i app at http://localhost:3000)
	docker run -d --rm --name p4i -v$(DIR):$(DIR)/p4src/build -w $(DIR)/p4src/build -p 3000:3000/tcp $(SDE_DOCKER_IMG) p4i

p4i-stop:
	docker kill p4i

reuse-lint:
	docker run --rm -v $(DIR):/fabric-tna -w /fabric-tna omecproject/reuse-verify:latest reuse lint

env:
	@cat $(RESOLVED_ENV) | grep -v "#"

clean:
	-rm -rf src/main/resources/p4c-out
	-rm -rf p4src/build
	-rm -rf target

deep-clean: clean
	-docker volume rm $(MVN_CACHE_DOCKER_VOLUME) > /dev/null 2>&1
