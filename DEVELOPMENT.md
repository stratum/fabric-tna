Getting Started (for developer)
====

# To build the basic pipeline profile

```bash
make fabric
```

# To run the PTF test

```bash
# The Stratum Docker image which includes the Stratum binary and libraries
export STRATUM_BF_DOCKER_IMG=stratumproject/stratum-bfrt:9.2.0
# (optional)Additional flags which helps you to modify the Stratum binary without rebuild the image
export STRATUM_BF_DOCKER_FLAG="-v abs-path-to-stratum_bfrt:/usr/bin/stratum_bfrt"
# The Docker image which includes the Tofino Model
export SDE_DOCKER_IMG=opennetworking/bf-sde:9.2.0

# Start the test
./ptf/run/tm/run fabric
```

To run the PTF test with test case
The name of test will be `test.[test class]`
You can find test case in `ptf/tests/ptf/fabric.ptf/test.py`, for example

```bash
./ptf/run/tm/run fabric TEST=test.FabricBridgingTest
```

