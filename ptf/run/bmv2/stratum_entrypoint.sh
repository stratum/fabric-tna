#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -ex

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

# From:
# https://github.com/p4lang/behavioral-model/blob/master/tools/veth_setup.sh

for idx in 0 1 2 3 4 5 6 7 8; do
    intf0="veth$((idx * 2))"
    intf1="veth$((idx * 2 + 1))"
    if ! ip link show $intf0 &> /dev/null; then
        ip link add name $intf0 type veth peer name $intf1
        ip link set dev $intf0 up
        ip link set dev $intf1 up

        # Set the MTU of these interfaces to be larger than default of
        # 1500 bytes, so that P4 behavioral-model testing can be done
        # on jumbo frames.
        # Note: ifconfig is deprecated, and no longer installed by
        # default in Ubuntu Linux minimal installs starting with
        # Ubuntu 18.04.  The ip command is installed in Ubuntu
        # versions since at least 16.04, and probably older versions,
        # too.
        ip link set $intf0 mtu 9500
        ip link set $intf1 mtu 9500

        # Disable IPv6 on the interfaces, so that the Linux kernel
        # will not automatically send IPv6 MDNS, Router Solicitation,
        # and Multicast Listener Report packets on the interface,
        # which can make P4 program debugging more confusing.
        #
        # Testing indicates that we can still send IPv6 packets across
        # such interfaces, both from scapy to simple_switch, and from
        # simple_switch out to scapy sniffing.
        #
        # https://superuser.com/questions/356286/how-can-i-switch-off-ipv6-nd-ra-transmissions-in-linux
        sysctl net.ipv6.conf.${intf0}.disable_ipv6=1
        sysctl net.ipv6.conf.${intf1}.disable_ipv6=1
    fi
done

stratum_bmv2 \
    -bmv2_log_level=trace \
    -chassis_config_file="${DIR}"/chassis_config.txt \
    -cpu_port=255 \
    -device_id=1 \
    -external-stratum-urls=0.0.0.0:28000 \
    -forwarding_pipeline_configs_file=/dev/null \
    -initial_pipeline=/root/dummy.json \
    -local_stratum_url=localhost:28000 \
    -log_dir="${DIR}"/log/ \
    -logtostderr=true \
    -persistent_config_dir=/tmp/ \
    -write_req_log_file="${DIR}"/log/p4rt-write-reqs.log \
    &> "${DIR}"/log/stratum_bmv2.log
