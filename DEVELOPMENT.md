Getting Started (for developer)
====

# To build the basic pipeline profile

Set the following environment variables:

```bash
# The Docker image which includes the bf-p4c compiler
export SDE_DOCKER_IMG=opennetworking/bf-sde:9.2.0
```

Start the build:

```bash
make fabric
```

# To run the PTF test

Obtain a Docker image which includes the stratum-bfrt binary and libraries:

```bash
scp onlbuilder@10.254.1.15:~/stratum-images/stratum-bfrt-9.2.0.tgz ./
docker load < /tmp/stratum-bfrt-9.2.0.tgz
```

NOTE: If you don't have access to 10.254.1.15 (buildsrv) ask Yi, Carmelo, or someone else in the Stratum team to add your SSH key.

Set the following environment variables:

```bash
# The Stratum Docker image which includes the stratum-bfrt binary and libraries
export STRATUM_BF_DOCKER_IMG=stratumproject/stratum-bfrt:9.2.0
# The Docker image which includes the Tofino Model.
# This should be the same used in the build step before.
export SDE_DOCKER_IMG=opennetworking/bf-sde:9.2.0
```

Start the test:

```bash
./ptf/run/tm/run fabric
```

To run the PTF test with test case
The name of test will be `test.[test class]`
You can find test case in `ptf/tests/ptf/fabric.ptf/test.py`, for example

```bash
./ptf/run/tm/run fabric TEST=test.FabricBridgingTest
```

For more instructions on how to run PTF tests, including where to
find logs, check `ptf/README.md`.

# Use stratum-bfrt binary without building a new Docker image

If you want to try a new stratum-bfrt build, but don't want to wait to build
a new Docker image for it, set the following env variable before running the PTF tests.

```
# Assuming you have build the stratum-bfrt binary in /path/to/stratum-bfrt
export STRATUM_BF_DOCKER_FLAG="-v /path/to/stratum-bfrt:/usr/bin/stratum_bfrt"
```

# To develop the pipeline with bf_switchd + bfrt_python CLI

Another way to manage the pipeline is to use bfrt_python CLI. This CLI also helps the developer to understand which table keys and data are supported by a table. (e.g., $MATCH_PRIORITY)

The Docker image `opennetworking/bf-sde:9.2.0-bfrt` includes SDE with all profiles.

The original compiler outputs are required for bfrt_python CLI.
Make sure `tmp` directory exists in the root of this repo after executing `make fabric` command.

To use this image:

```bash
cd fabric-tna # enter this dir

# Start the Docker container with privileged and mount this directory
docker run -it --rm -v $PWD:$PWD -w $PWD --privileged --name tofino-model opennetworking/bf-sde:9.2.0-bfrt

# Set up veth pairs
veth_setup.sh

# Set up DMA
dma_setup.sh

# Start the Tofino Model with fabric_tna pipeline
$SDE/run_tofino_model.sh -c tmp/fabric/mavericks_sde_9_2_0/fabric_tna.conf -p fabric_tna
```

After the Tofino Model started, use `docker exec` command to start another bash shell so we can start the bf_switchd

```bash
docker exec -it tofino-model bash

# Start the bf_switchd process
$SDE/run_switchd.sh -c tmp/fabric/mavericks_sde_9_2_0/fabric_tna.conf
```

Now you can use `bfrt_python` command to manage the pipeline.
