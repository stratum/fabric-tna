<!--
Copyright 2020-present Open Networking Foundation
SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
-->

# Fabric-TNA

[![Build Status](https://jenkins.onosproject.org/buildStatus/icon?job=fabric-tna-postmerge)](https://jenkins.onosproject.org/job/fabric-tna-postmerge/)

`fabric-tna` is a P4 program designed to work with [Trellis](trellis), a set of
SDN applications running on top of ONOS to provide the control plane for an IP
fabric based on MPLS segment-routing.

`fabric-tna.p4` is based on the Tofino Native Architecture (TNA), hence it
can be used to program any switch based on the Intel Barefoot Tofino ASIC.

`fabric-tna.p4` is not to be confused with [fabric.p4], which is based on the
v1model architecture and is hosted in the ONOS repository. `fabric-tna.p4`
follows a similar design to `fabric.p4`, but has evolved significantly to
provide more advanced capabilities for Inband Network Telemetry (INT) and 45/5G
mobile user plane (a.k.a. SPGW in 4G or UPF in 5G).

To use ONOS to control a Tofino switch, you will need to run the
[Stratum][stratum] agent on the switch.

## Requirements

* Barefoot SDE (a.k.a. Intel P4 Studio) = 9.3.1
* ONOS >= 2.5.1
* Docker (to run the build scripts without worrying about dependencies)
* cURL (to interact with the ONOS REST APIs)

## Quick steps

To compile the P4 program with a given `<profile>` configuration and using a
containerized version of the Barefoot SDE:

```bash
make <profile> SDE_DOCKER_IMG=my-docker-repo/bf-sde:9.3.1
```

The available profiles are:

| Profile name            | Description                                        |
| ------------------------|----------------------------------------------------|
| `fabric`                | Basic Trellis IP/MPLS forwarding capabilities      |
| `fabric-bng`            | With BNG user plane support (Not available yet)    |
| `fabric-spgw`           | With 4G/5G mobile user plane support               |
| `fabric-int`            | With INT support                                   |
| `fabric-spgw-int`       | WITH SPGW and INT support                          |

To run PTF tests on Stratum using `tofino-model`:

```bash
SDE_DOCKER_IMG=my-docker-repo/bf-sde:9.3.1 ./ptf/run/tm/run <profile>
```

To build the ONOS pipeconf `.oar` package which includes the compiled P4
artifacts for the previously built profile(s):

```bash
make pipeconf
```

To learn more about pipeconfs, keep reading.

For more information about running PTF tests, check [ptf/README.md](ptf/README.md).

## Detailed steps to build the fabric-tna pipeconf

ONOS uses "pipeconfs" to deploy and manage a given P4 program on a device.
Pipeconfs include mainly two things:

1. the P4 compiled artifacts (e.g., `tofino.bin`, `context.json`, etc.) to
deploy on devices.
2. Java classes implementing ONOS driver behaviors to control capabilities of
the particular P4 program.

Pipeconfs are distributed as ONOS applications, hence using the `.oar`
packaging. The following steps provide instructions on how to generate an oar
package that includes one or more profiles.

The code is organized as follows:
* `p4src`: contains the P4 code
* `ptf`: contains PTF tests for the P4 code
* `src`: contains Java implementation and tests for the pipeconf

To learn more about pipeconfs and how ONOS supports P4-programmable devices:
<https://github.com/opennetworkinglab/ngsdn-tutorial>

To build `fabric-tna.p4` using the Barefoot compiler and to create the pipeconf
`.oar` package in one command:

```bash
make build PROFILES=all
```

This command will build the `fabric-tna.p4` profiles specified in the
`PROFILES` argument.

To build all profiles: `PROFILES=all`.

To build a subset of the available profiles separate them with whitespaces:
`PROFILES="fabric fabric-int"`

The P4 compiler outputs to include in the `.oar` package will be placed under
`src/main/resources/p4c-out`.

When done, the pipeconf `.oar` package can be found in
`target/fabric-tna-<VERSION>.oar`

### Using containerized version of the Barefoot SDE

The build script supports using a Docker-based distribution of the Barefoot SDE.
To do so, simply set the `SDE_DOCKER_IMG` make argument (or environment
variable) to a Docker image, for example:

```bash
make build SDE_DOCKER_IMG=my-docker-repo/bf-sde:9.3.1-p4c PROFILES=all
```

When building the P4 program, the build script will use `docker run` to invoke
the `bf-p4c` command inside the given image. For this reason, the script expects
a Docker image that has the whole Barefoot SDE installed in it or just the p4c
package. In both cases, the `bf-p4c` executable should be on `PATH`. We do not
provide such image, but one can be easily generated by executing the SDE install
instructions inside a Dockerfile.

## Steps to use the fabric-tna pipeconf with ONOS

### 1 - Get and run ONOS

The minimum required ONOS version that works with this pipeconf is 2.2.7.

You can either build from sources (using the `onos-2.2` or `master` branch), or
run one the released versions:
<https://wiki.onosproject.org/display/ONOS/Downloads>

Pre-built ONOS Docker images are available here:
<https://hub.docker.com/r/onosproject/onos/tags>

For more information on how to get and run ONOS:
<https://wiki.onosproject.org/display/ONOS/Guides>

### 2 - Start Stratum on your switch

For instructions on how to install and run Stratum on a Tofino switch:
<https://github.com/stratum/stratum/tree/master/stratum/hal/bin/barefoot>

### 3 - Install pipeconf app in ONOS

To install the pipeconf app built in the previous step, assuming ONOS is
running on the local machine:

```bash
make pipeconf-install ONOS_HOST=localhost
```

Use the `ONOS_HOST` argument to specify the hostname/IP address of the machine
where ONOS is running.

This command is a wrapper to a `curl` command that uses the ONOS REST API to
upload and activate the `.oar` package previously built.

You should see the ONOS log updating with messages notifying the registration of
new pipeconfs in the system, depending on the profiles compiled before, and the
Barefoot SDE version:

```text
New pipeconf registered: org.stratumproject.fabric.mavericks_sde_9_3_1 (fingerprint=...)
New pipeconf registered: org.stratumproject.fabric.montara_sde_9_3_1 (fingerprint=...)
...
```

**NOTE: it might take up to one minute for the pipeconfs to be registered.**

To check all pipeconfs registered in the system, use the ONOS CLI:

```text
onos> pipeconfs
```

### 4 - Connect ONOS to a Stratum switch

Activate the Barefoot drivers in ONOS:

```text
onos> app activate org.onosproject.drivers.barefoot
```

This command will register a new driver named `stratum-tofino`. As the name
suggests, this driver allows ONOS to control Tofino switches running Stratum.

For ONOS to be able to discover your switch, you need to push a JSON file,
usually referred to as the "netcfg" file. We provide an example of such
`tofino-netcfg.json` file in this repository. Make sure to modify the following
values:

* `managementAddress` is expected to contain a valid URI with host and port of
  the Stratum gRPC server running on the switch;
* The `device_id` URI query parameter is the P4Runtime-internal `device_id`,
  also known as the Stratum "Node ID". Usually, you can leave this value set to
  `1`;
* Use the `pipeconf` field to specify which pipeconf/fabric profile to deploy on
  the switch.

Push the `tofino-netcfg.json` to ONOS using the command:

```bash
make netcfg ONOS_HOST=localhost
```

Like before, this command is a wrapper to a `curl` command that uses the ONOS
REST API to push the `tofino-netcfg.json` file.

Check the ONOS log for potential errors.

## Using Trellis with Stratum+Tofino switches

Check the official Trellis documentation here:
<https://docs.trellisfabric.org>

In the "Device Configuration" section:
<https://docs.trellisfabric.org/configuration/device-config.html>

make sure to replace the `basic` JSON node for OpenFlow devices with the one
provided in `tofino-netcfg.json`, for example:

```json
{
  "devices" : {
    "device:leaf-1" : {
      "segmentrouting" : {
        "ipv4NodeSid" : 101,
        "ipv4Loopback" : "192.168.0.201",
        "ipv6NodeSid" : 111,
        "ipv6Loopback" : "2000::c0a8:0201",
        "routerMac" : "00:00:00:00:02:01",
        "isEdgeRouter" : true,
        "adjacencySids" : []
      },
      "basic": {
        "managementAddress": "grpc://10.0.0.1:28000?device_id=1",
        "driver": "stratum-tofino",
        "pipeconf": "org.stratumproject.fabric.montara_sde_9_3_1"
      }
    }
  }
}
```

## Support

To report issues when compiling `fabric-tna.p4` for Tofino (i.e., P4 compiler
errors), please contact Intel/Barefoot support.

To report any other kind of problem, feel free to open a GitHub Issue or reach
out to the project maintainers on the ONF Community Slack.

[stratum]: https://github.com/stratum/stratum
[trellis]: https://www.opennetworking.org/trellis
[fabric.p4]: https://github.com/opennetworkinglab/onos/tree/master/pipelines/fabric/impl/src/main/resources
