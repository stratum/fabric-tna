# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
import logging
import collections
from scapy.layers.all import IP, TCP, UDP, Ether

# This file contains commons functions and constants related to QoS.
# For consistency, all QoS test code should utilize them as much as
# possible.

# MAC addresses for test use.
SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:02"

# Semantic queue IDs
QUEUE_ID_BEST_EFFORT = 0
QUEUE_ID_SYSTEM = 1
QUEUE_ID_CONTROL = 2

# Canonical L4 ports for different test traffic classes.
L4_DPORT_BEST_EFFORT_TRAFFIC = 1000
L4_DPORT_SYSTEM_TRAFFIC = 1001
L4_DPORT_CONTROL_TRAFFIC = 1002

# Returns a packet that belongs to the control CoS group.
def get_control_traffic_packet(l2_size=64):
    pkt = Ether(dst=DEST_MAC) / IP() / UDP(dport=L4_DPORT_CONTROL_TRAFFIC) / ("*" * (l2_size - 42))
    assert(len(pkt) == l2_size), "Packet size {} does not match target size {}".format(len(pkt), l2_size)
    return pkt
