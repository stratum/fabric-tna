#!/bin/bash

export STRATUM_BF_DOCKER_IM=stratumproject/stratum-bfrt:20.12-9.3.1
export SDE_DOCKER_IMG=opennetworking/bf-sde:9.3.1

./ptf/run/tm/run fabric-conquest $@
