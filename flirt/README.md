<!--
SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
SPDX-License-Identifier: Apache-2.0
-->

# Fabric Line Rate Test

![Python Code Style](https://github.com/stratum/fabric-line-rate-test/workflows/Super%20Linter/badge.svg)
![REUSE](https://github.com/stratum/fabric-line-rate-test/workflows/REUSE/badge.svg)
![Container Image](https://github.com/stratum/fabric-line-rate-test/workflows/Container%20Image/badge.svg)

Scripts and configs to run line rate test

## Requirements

- make
- Docker (Tested with 19.03.13 on MacOS)
- Trex 2.85 (On the server)

## Repository structure

```text
├── Dockerfile
├── Makefile
├── README.md
├── stratum ----------> Configs for stratum
├── tost -------------> Configs to start TOST control plane
├── trex-configs -----> Configs to start Trex server
└── trex-scripts
    ├── control.py ---> The entrypoint of test
    ├── lib ----------> Utility for test
    └── tests --------> Test scripts
```

## Getting started

### Build the container image

Here we provide a container image that includes all necessary Trex Python dependencies.
To build the container image, use the following command:

```bash
make build-image
```

### Set up the development environment with Python venv

> Developer only

If you are going to develop Python scripts in this project with
modern IDEs (e.g, VS Code), you can install libraries so the IDE can
provide better support.
We use python [venv][venv] tool to create a virtual environment so we won't
mess up the system libraries.

Note that you need to build the container image first, since the
setup script will copy the Trex libraries from the image.

To set up the environment, use the following command:

```bash
make set-up-dev-env
```

This command will create a `.venv` directory and install libraries based on `requirements.txt`,
it also copies libraries from the container we just built in previous step.

Some modern IDEs will detected the virtual environment and use it directly.

### Set up test environment

To run a test, you need to:

- Start Trex daemon server
- Set up a Stratum device
- Install flows to the device (via ONOS, P4Runtime shell, or stratum-replay tool)
- Run test script and verify the result

#### Start Trex daemon server

To start Trex daemon, run the following command on the server

```bash
cd [trex root]/scripts
sudo ./trex_daemon_server start[-live]
```

Make sure the Trex service ports (4500, 4501, 4507, and 8090) are accessable from
the machine which runs test scripts.

#### Set up a Stratum device

See [Stratum guide][stratum-guide]

#### Install flows to the device

Here we provide a basic script to start TOST(Trellis, ONOS, Stratum Tofino) control
plane.

Use `make onos-start` to start the ONOS container, and use `make onos-log` command to
check the ONOS log, and wait until every applications are loaded.

Next is to push the network config to ONOS. Before push the config, remember to modify
the management address in the config file [tost/netcfg.json](tost/netcfg.json).

Now you can use `mane netcfg` to push the network config to ONOS. And ONOS should start
connecting to the deivce.

You can also use `make onos-cli` to access the command line and check state of components
like interface, port, device, flows.

For INT test, remember to add INT watch list rules via [ONOS web UI](onos-ui).

### Run test script and verify the result

To run a test, use following command:

```bash
./run-test.sh --server-addr [server address] --trex-config [trex-config] test-name ...
```

The `run-test.sh` script will start a base container which includes all necessary
dependencies for the test script. It also mounts the `trex-script` and `tmp` dir from
the host to the container.
The `trex-script` will be mounted to the `/workspace/trex-script`, and `tmp`
will be mounted to `/tmp`. In most of cases, some temporary files such as config or
INT report pcap files will be shared via this directory.

## Develop a new test

### Create Trex config for test (optional)

We provide an example trex-config which includes 4 40G interfaces in the
[trex-configs](trex-configs) directory.

Below is a sample Trex config

```yaml
- version: 2
  interfaces: ['3b:00.0', '3b:00.1']
  port_bandwidth_gb: 40
```

This config file includes two ports, which will be port 0 and port 1 in the test.

For more information about Trex cofig, checkout the [Trex manual][trex-manual]

### Create a new test script

Create a new python script and place it to [trex-scripts/tests](trex-scripts/tests)

Here is an example of the test script:

```python
from argparse import ArgumentParser
from lib.base_test import BaseTest

# Each test need to inherit the BaseTest
# The following member will be initialized:
# self.stl_client: The Trex client for stateless server
class SimpleTcpTest(BaseTest):

    # setup_subparser is an optional class method
    # You can implement this method if you want to add additional command line
    # parameters for your test.
    # Those parameters will be parsed and be passed to the "start" method below as
    # "args" argument.
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--mult",
            type=str,
            help="Traffic multifier",
            default="1pps"
        )
        parser.add_argument(
            "--duration",
            type=int,
            help="Duration of the test",
            default=5 # seconds
        )

    # The entry point of a test
    def start(self, args) -> None:
        # Here, you can create any type of traffic based on different packet type
        # for example, create a basic TCP by using scapy library
        pkt = Ether() / IP() / TCP() / "payload" * 10

        # Create a traffic stream
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())

        # Start sending traffic
        self.stl_client.add_streams(stream, ports=[0])
        self.stl_client.start(ports=[0], mult=args.mult, duration=args.duration)

        # Wait until traffic stop
        self.stl_client.wait_on_traffic(ports=[0])
```

For more information, check the [Trex stateless SDK manual](trex-stateless-sdk) and
[the cookbook](trex-cookbook)

[trex-manual]: https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_platform_yaml_cfg_argument
[venv]: https://docs.python.org/3.8/library/venv.html
[stratum-guide]: https://github.com/stratum/stratum/blob/master/stratum/hal/bin/barefoot/README.md
[onos-ui]: http://127.0.0.1:8181/onos/ui
[trex-stateless-sdk]: https://trex-tgn.cisco.com/trex/doc/cp_stl_docs/index.html
[trex-cookbook]: https://trex-tgn.cisco.com/trex/doc/trex_cookbook/index.html
