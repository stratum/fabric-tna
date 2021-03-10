include util/Makefile.vars

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
curr_dir := $(patsubst %/,%,$(dir $(mkfile_path)))

APP_NAME := p4rtt-app
onos_url := http://localhost:8181/onos
onos_curl := curl --fail -sSL --user onos:rocks --noproxy localhost

ONOS_P4_SUBPATH := pipelines/fabric/impl/src/main/resources

BAZEL_IMG := insready/bazel:latest

ONOS_ROOT := ${curr_dir}/onos
ONOS_APPS := gui2,drivers.bmv2,lldpprovider,hostprovider,segmentrouting,netcfghostprovider

_p4rt-sh:
	docker run -ti --network host p4lang/p4runtime-sh \
	--grpc-addr localhost:${DEV_PORT} \
	--device-id 1 --election-id 0,1 # change 0,1 to 1,1 to steal master from ONOS

p4rt-sh:
	# you can only run this after the netcfg has been pushed
	make _p4rt-sh DEV_PORT=50001 # netcfg tells you which port to use for which device

_onos_start:
	cd onos && ONOS_APPS=${ONOS_APPS} bazel run onos-local -- clean

start:
	@mkdir -p tmp/onos
	@docker-compose up -d
	sleep 1
	@echo "Launching ONOS"
	make _onos_start

stop:
	@docker-compose down

stop-quick:
	# for if your docker-compose installation supports the t0 flag
	@docker-compose down -t0

onos-ui:
	open ${onos_url}/ui

onos-logs:
	docker-compose logs -f onos

onos-cli:
	@echo "Password: rocks"
	ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o LogLevel=ERROR -p 8101 onos@localhost

_docker_pull_all:
	docker pull ${P4C_IMG}@${P4C_SHA}
	docker tag ${P4C_IMG}@${P4C_SHA} ${P4C_IMG}
	docker pull ${MAVEN_IMG}@${MAVEN_SHA}
	docker tag ${MAVEN_IMG}@${MAVEN_SHA} ${MAVEN_IMG}
	docker pull ${ONOS_IMG}@${ONOS_SHA}
	docker tag ${ONOS_IMG}@${ONOS_SHA} ${ONOS_IMG}

_get_onos_tools:
	rm -rf onos-tools
	curl -sS --fail https://repo1.maven.org/maven2/org/onosproject/onos-releases/2.2.2/onos-admin-2.2.2.tar.gz \
		> tools.tar.gz
	tar xf tools.tar.gz
	mv onos-admin-2.2.2 onos-tools
	rm tools.tar.gz

_clone_onos:
	git clone -b onos-2.2 https://github.com/opennetworkinglab/onos.git

deps: _get_onos_tools _docker_pull_all _clone_onos

app-build:
	docker run -it --rm -v ${HOME}/.m2:/root/.m2 \
		-v ${PWD}/${APP_NAME}:/root/${APP_NAME} -w /root/${APP_NAME} maven:3.6.3-openjdk-11-slim \
		mvn clean install

app-load:
	./onos-tools/onos-app localhost install! ${APP_NAME}/target/${APP_NAME}-1.0.oar

app-reload:
	./onos-tools/onos-app localhost reinstall! ${APP_NAME}/target/${APP_NAME}-1.0.oar

p4-build:
	cd p4src && make fabric-p4rtt

pipeconf-build:
	rm -rf onos/${ONOS_P4_SUBPATH}/* # clear out the old p4 programs from ONOS
	cp -r p4src/* onos/${ONOS_P4_SUBPATH}/ # copy ours into ONOS
#	cd onos/${ONOS_P4_SUBPATH}/ && ONOS_ROOT=${ONOS_ROOT} make all # build the copied p4 programs
	cd onos/${ONOS_P4_SUBPATH}/ && ONOS_ROOT=${ONOS_ROOT} make fabric-p4rtt # build the copied p4 programs
	#cd onos && docker run --rm -v `pwd`:/onos -w /onos -d ${BAZEL_IMG} bazel build //pipelines/fabric:onos-pipelines-fabric-oar
	cd onos && bazel build //pipelines/fabric:onos-pipelines-fabric-oar # build pipeconf

pipeconf-load:
	./onos-tools/onos-app localhost install! onos/bazel-bin/pipelines/fabric/onos-pipelines-fabric-oar.oar

pipeconf-reload:
	./onos-tools/onos-app localhost reinstall! onos/bazel-bin/pipelines/fabric/onos-pipelines-fabric-oar.oar

fabric-check:
	./check_fabric.sh fabric


netcfg:
	$(info *** Pushing ./util/netcfg.json to ONOS...)
	${onos_curl} -X POST -H 'Content-Type:application/json' \
		${onos_url}/v1/network/configuration -d@./util/netcfg.json
	@echo

fabric-oar:
	./onos-tools/onos-app localhost reinstall! ${APP_NAME}/target/${APP_NAME}-0.1.oar



onos-config: pipeconf-reload app-load netcfg


mn-cli:
	$(info *** Attaching to Mininet CLI...)
	$(info *** To detach press Ctrl-D (Mininet will keep running))
	-@docker attach --detach-keys "ctrl-d" $(shell docker-compose ps -q mininet) || echo "*** Detached from Mininet CLI"
