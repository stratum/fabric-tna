<!--
Copyright 2020-present Open Networking Foundation
SPDX-License-Identifier: Apache-2.0
-->

# Fabric-TNA Pipeconf

This repository contains instructions and scripts to compile and use
`fabric-tna.p4` on Intel/Barefoot Tofino-enabled switches.

[fabric.p4][fabric.p4] is a P4 program distributed as part of ONOS, designed to
work with [Trellis](trellis), a set of SDN applications running on top of ONOS
to provide the control plane for an IP fabric based on MPLS segment-routing.

`fabric-tna.p4` is a new P4 program which ports the original `fabric.p4` to
the Tofino Native Architecture(TNA).

To use ONOS to control a Tofino-enabled switch, you will need to run the
[Stratum][stratum] agent on the switch.

## Requirements

* Barefoot SDE >= 9.2.0 (with the P4_16 compiler for Tofino)
* ONOS >= 2.2.3
* Docker (to run the build scripts without worrying about dependencies)
* cURL (to interact with the ONOS REST APIs)

## Steps to build Tofino-enabled fabric-tna.p4 pipeconfs

ONOS uses "pipeconfs" to deploy and manage a given P4 program on a device.
Pipeconfs are distrubuted as ONOS applications, hence using the `.oar`
packaging. The following steps provide instructions on how to generate an oar
package that includes a compiled version of `fabric-tna.p4` that works on Tofino.

* `src/main/java`: contains Java code that implements the ONOS app responsible
  for registering the Tofino-enabled pipeconfs in ONOS;
* `src/main/p4`: contains code to compile fabric-tna.p4 for Tofino.

To learn more about pipeconfs and how ONOS supports P4-programmable devices:
<https://github.com/opennetworkinglab/ngsdn-tutorial>

### 1 - Build Tofino-enabled fabric-tna pipeconf

To build `fabric-tna.p4` using the Barefoot compiler and to create the pipeconf
`.oar` package:

```bash
cd fabric-tna # this repo
make build PROFILES=all
```

#### Fabric-TNA profiles

The above command will build the `fabric-tna.p4` profiles specified in the
`PROFILES` argument. Possible values are:

| Profile name            | Description                                        |
| ------------------------|----------------------------------------------------|
| `fabric`                | Basic profile                                      |
| `fabric-bng`            | With BNG user plane support (Not available)        |
| `fabric-spgw`           | With SPGW user plane support                       |
| `fabric-int`            | With INT support                                   |
| `fabric-spgw-int`       | WITH SPGW and INT support                          |

Check the `Makefile` for other profiles.

To build all profiles: `PROFILES=all`.

To build a subset of the available profiles: `PROFILES="fabric fabric-bng"`

The P4 compiler outputs to include in the `.oar` package (such as `tofino.bin`,
`context.json`, and `p4info.txt`) will be placed under
`src/main/resources/p4c-out`.

When done, the pipeconf `.oar` package can be found in
`target/fabric-tofino-<VERSION>.oar`

#### Using containerized version of the Barefoot SDE / p4c compilers

The previous command expects the `bf-p4c` compiler to be installed locally. As an
alternative, the build script supports using a Docker-based distribution of the
Barefoot SDE / p4c compilers. To do so, simply set the `SDE_DOCKER_IMG`
make argument (or environment variable) to a Docker image that can be downloaded
via `docker pull`, for example:

```bash
make build SDE_DOCKER_IMG=my-docker-repo/bf-sde:9.2.0 PROFILES=all
```

The build script will use `docker run` to invoke the `bf-p4c` command inside the
given image. For this reason, the script expects a Docker image that has the
whole Barefoot SDE installed in it or just the p4c package. In both cases, the
`bf-p4c` executable should be on `PATH`. We do not provide such image, but one
can be easily generated by executing the SDE install instructions inside a
Dockerfile.

#### Using Barefoot P4 Insight

```bash
make p4i
make p4i-stop
```

## Steps to use the Tofino-enabled fabric-tna pipeconf with ONOS

### 1 - Get and run ONOS

The minimum required ONOS version that works with this pipeconf is 2.2.3.

You can either build from sources (using the `onos-2.2` or `master` branch), or
run one the released versions:
<https://wiki.onosproject.org/display/ONOS/Downloads>

Pre-built ONOS Docker images are available here:
<https://hub.docker.com/r/onosproject/onos/tags>

For more information on how to get and run ONOS:
<https://wiki.onosproject.org/display/ONOS/Guides>

### 2 - Start Stratum on your switch

For instructions on how to install and run Stratum on Tofino-enabled switches:
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
new Tofino-specific pipeconfs in the system, depending on the `fabric-tna.p4`
profiles compiled before and the Barefoot SDE/p4c version used:

```
New pipeconf registered: org.stratumproject.fabric.stratum_bfrt.mavericks_sde_9_2_0 (fingerprint=...)
New pipeconf registered: org.stratumproject.fabric.stratum_bfrt.montara_sde_9_2_0 (fingerprint=...)
...
```

**NOTE: it might take up to one minute for the pipeconfs to be registered.
This is currently a bug and will be fixed soon.**

To check all pipeconfs registered in the system, use the ONOS CLI:

```
onos> pipeconfs
```

### 4 - Connect ONOS to a Stratum switch

Activate the Barefoot drivers in ONOS:

```
onos> app activate org.onosproject.drivers.barefoot
```

This command will register a new driver named `stratum-tofino`. As the name
suggests, this driver allows ONOS to control Tofino-enabled Stratum switches.

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

```
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
        "pipeconf": "org.stratumproject.fabric.tofino.montara_sde_9_2_0"
      }
    }
  }
}
```

## Support

To report issues when compiling `fabric-tna.p4` for Tofino (i.e., compiler errors), please contact Intel/Barefoot support.

To get help with ONOS and the fabric-tna pipeconf, please contact
<brigade-p4@onosproject.org> (this is a public mailing list, please beware of
not discussing information under Intel/Barefoot NDA)

[stratum]: https://github.com/stratum/stratum
[trellis]: https://www.opennetworking.org/trellis
[fabric.p4]: https://github.com/opennetworkinglab/onos/tree/master/pipelines/fabric/impl/src/main/resources
