<!-- Copyright 2020-present Open Networking Foundation -->
<!-- SPDX-License-Identifier: LicenseRef-ONF-Member-1.0 -->

# Getting Started (for developer)

## To build the basic pipeline profile

Set the following environment variables:

```bash
# The Docker image which includes the bf-p4c compiler
export SDE_DOCKER_IMG=opennetworking/bf-sde:9.2.0
```

Build the P4 program specifying the desired profile:

```bash
# fabric, fabric-int, fabric-spgw, and fabric-spgw-int
make fabric
```

## Run PTF tests using stratum-bfrt

Start the tests for the same profile built in the previous step

```bash
./ptf/run/tm/run fabric
```

To run PTF for a specific test case:

```bash
./ptf/run/tm/run fabric TEST=test.FabricBridgingTest
```

The value of `TEST` should be `test.[test class]`, you can find test clases in
`ptf/tests/ptf/fabric.ptf/test.py`.

For more instructions on how to run PTF tests, including where to
find logs, check `ptf/README.md`.

## Use an external stratum-bfrt binary without building a new Docker image

If you want to try a new stratum-bfrt build, but don't want to wait to build
a new Docker image for it, set the following env variable before running the PTF tests.

```bash
# Assuming you have build the stratum-bfrt binary in /path/to/stratum-bfrt
export STRATUM_BF_DOCKER_FLAG="-v /path/to/stratum-bfrt:/usr/bin/stratum_bfrt"
```

## To develop the pipeline with bf_switchd + bfrt_python CLI

Another way to manage the pipeline is to use bfrt_python CLI. This CLI also
helps the developer to understand which table keys and data are supported
by a table. (e.g., $MATCH_PRIORITY)

The Docker image `opennetworking/bf-sde:9.2.0-bfrt` includes SDE with all profiles.

The original compiler outputs are required for bfrt_python CLI.
Make sure `p4src/build/<PROFILE>` directory exists in the root of this repo
after executing `make <profile>` command.

To use this image:

```bash
# Start the Docker container with privileged and mount this directory
docker run -it --rm -v $PWD:$PWD -w $PWD --privileged --name tofino-model opennetworking/bf-sde:9.2.0-bfrt

# Set up veth pairs
veth_setup.sh

# Set up DMA
dma_setup.sh

# Start the Tofino Model with fabric_tna pipeline
$SDE/run_tofino_model.sh -c p4src/build/fabric/sde_9_2_0/fabric_tna.conf -p fabric_tna
```

After the Tofino Model started, use `docker exec` command to start another bash shell so we can start the bf_switchd

```bash
docker exec -it tofino-model bash

# Start the bf_switchd process
$SDE/run_switchd.sh -c tmp/fabric/mavericks_sde_9_2_0/fabric_tna.conf
```

Now you can use `bfrt_python` command to manage the pipeline.
