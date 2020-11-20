#!/usr/bin/env bash
# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

set -ex

# From:
# https://github.com/p4lang/behavioral-model/blob/master/tools/veth_setup.sh

for _ in $(seq 1 $#); do
    intf0=$1
    intf1="$1_peer"
	shift
    if ! ip link show "$intf0" &> /dev/null; then
        ip link add name "$intf0" type veth peer name "$intf1"
        ip link set dev "$intf0" up
        ip link set dev "$intf1" up

        # Set the MTU of these interfaces to be larger than default of
        # 1500 bytes, so that P4 behavioral-model testing can be done
        # on jumbo frames.
        # Note: ifconfig is deprecated, and no longer installed by
        # default in Ubuntu Linux minimal installs starting with
        # Ubuntu 18.04.  The ip command is installed in Ubuntu
        # versions since at least 16.04, and probably older versions,
        # too.
        ip link set "$intf0" mtu 9500
        ip link set "$intf1" mtu 9500

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
        #sysctl net.ipv6.conf.${intf0}.disable_ipv6=1
        #sysctl net.ipv6.conf.${intf1}.disable_ipv6=1
    fi
done

