#!/bin/bash

export STRATUM_BF_DOCKER_IM=stratumproject/stratum-bfrt:20.12-9.2.0
export SDE_DOCKER_IMG=opennetworking/bf-sde:9.2.0

./ptf/run/tm/run fabric-conquest $@
