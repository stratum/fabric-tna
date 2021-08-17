# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
import collections
import logging

import ptf.testutils as testutils
from scapy.layers.all import IP, TCP, UDP, Ether

# This file contains commons functions and constants related to QoS.
# For consistency, all QoS test code should utilize them as much as
# possible.

# MAC addresses for test use.
SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:02"

# Semantic queue IDs. Must match the queue_mappings in chassis config!
QUEUE_ID_BEST_EFFORT = 0
QUEUE_ID_SYSTEM = 1
QUEUE_ID_CONTROL = 2
QUEUE_ID_REALTIME_1 = 3
QUEUE_ID_REALTIME_2 = 4
QUEUE_ID_REALTIME_3 = 5
QUEUE_ID_ELASTIC_1 = 6
QUEUE_ID_ELASTIC_2 = 7

# Canonical L4 ports for different test traffic classes.
L4_DPORT_BEST_EFFORT_TRAFFIC_1 = 1000
L4_DPORT_BEST_EFFORT_TRAFFIC_2 = 1001
L4_DPORT_ELASTIC_TRAFFIC = 2000
L4_DPORT_SYSTEM_TRAFFIC = 3000
L4_DPORT_REALTIME_TRAFFIC_1 = 4000
L4_DPORT_REALTIME_TRAFFIC_2 = 4001
L4_DPORT_REALTIME_TRAFFIC_3 = 4002
L4_DPORT_CONTROL_TRAFFIC = 5000
L4_DPORT_ELASTIC_TRAFFIC_1 = 6000
L4_DPORT_ELASTIC_TRAFFIC_2 = 6001

# Returns a packet that belongs to the control CoS group.
def get_control_traffic_packet(l2_size=64):
    pkt = testutils.simple_udp_packet(
        eth_dst=DEST_MAC, udp_dport=L4_DPORT_CONTROL_TRAFFIC, pktlen=l2_size
    )
    assert len(pkt) == l2_size, "Packet size {} does not match target size {}".format(
        len(pkt), l2_size
    )
    return pkt


# Returns a packet that belongs to the realtime CoS group.
def get_realtime_traffic_packet(l2_size=64, dport=L4_DPORT_REALTIME_TRAFFIC_1):
    assert (
        L4_DPORT_REALTIME_TRAFFIC_1 <= dport <= L4_DPORT_REALTIME_TRAFFIC_3
    ), "Invalid dport"
    pkt = testutils.simple_udp_packet(eth_dst=DEST_MAC, udp_dport=dport, pktlen=l2_size)
    assert len(pkt) == l2_size, "Packet size {} does not match target size {}".format(
        len(pkt), l2_size
    )
    return pkt


# Returns a packet that belongs to the elastic CoS group.
def get_elastic_traffic_packet(l2_size=64, dport=L4_DPORT_ELASTIC_TRAFFIC_1):
    assert (
        L4_DPORT_ELASTIC_TRAFFIC_1 <= dport <= L4_DPORT_ELASTIC_TRAFFIC_2
    ), "Invalid dport"
    pkt = testutils.simple_udp_packet(eth_dst=DEST_MAC, udp_dport=dport, pktlen=l2_size)
    assert len(pkt) == l2_size, "Packet size {} does not match target size {}".format(
        len(pkt), l2_size
    )
    return pkt


# Returns a packet that belongs to the system CoS group.
def get_system_traffic_packet(l2_size=64):
    pkt = testutils.simple_udp_packet(
        eth_dst=DEST_MAC, udp_dport=L4_DPORT_SYSTEM_TRAFFIC, pktlen=l2_size
    )
    assert len(pkt) == l2_size, "Packet size {} does not match target size {}".format(
        len(pkt), l2_size
    )
    return pkt


# Returns a packet that belongs to the best-effort CoS group.
def get_best_effort_traffic_packet(l2_size=1400, dport=L4_DPORT_BEST_EFFORT_TRAFFIC_1):
    pkt = testutils.simple_udp_packet(eth_dst=DEST_MAC, udp_dport=dport, pktlen=l2_size)
    assert len(pkt) == l2_size, "Packet size {} does not match target size {}".format(
        len(pkt), l2_size
    )
    return pkt
