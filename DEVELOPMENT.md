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
