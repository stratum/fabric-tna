# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

# This test empirically checks that a minimal expected flow rate with latency
# measurements (STLFlowLatencyStats) is supported by Trex.

import json
import logging
import os

from base_test import *
from fabric_test import *
from trex_test import TRexTest
from trex_utils import *
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import *

import qos_utils
import gnmi_utils

TRAFFIC_DURATION_SECONDS = 10

L2_PACKET_SIZE = 64
EXPECTED_FLOW_RATE_WITH_STATS_BPS = 1 * G

TX_PORT = [0]
ALL_SENDER_PORTS = [0]
RX_PORT = [1]
ALL_PORTS = [0, 1, 2]

class MinFlowrateWithSoftwareLatencyMeasurement(TRexTest, FabricTest):
    def push_chassis_config(self) -> None:
        chassis_config = b""
        with open("../linerate/chassis_config_for_qos_strict_priority.pb.txt", mode='rb') as file:
            chassis_config = file.read()
        gnmi_utils.push_chassis_config(chassis_config)

    def setup_flow_state(self) -> None:
        self.setup_port(self.port1, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port2, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port3, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port1)

    # Create a highest priority control stream.
    def create_control_stream(self, pg_id) -> STLStream:
        pkt = qos_utils.get_control_traffic_packet(L2_PACKET_SIZE)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=EXPECTED_FLOW_RATE_WITH_STATS_BPS),
            flow_stats = STLFlowLatencyStats(pg_id = pg_id))

    @autocleanup
    def runTest(self):
        pg_id = 7
        self.push_chassis_config()
        self.setup_flow_state()
        # Put RX ports to promiscuous mode, otherwise it will drop all packets
        # if the destination mac is not the port mac address.
        self.trex_client.set_port_attr(ALL_PORTS, promiscuous=True)
        # Create the control stream
        control_stream = self.create_control_stream(pg_id)
        self.trex_client.add_streams(control_stream, ports=TX_PORT)

        # Start sending traffic
        logging.info(
            "Starting traffic, duration: %d sec", TRAFFIC_DURATION_SECONDS,
        )
        self.trex_client.start(ALL_SENDER_PORTS, mult='1', duration=TRAFFIC_DURATION_SECONDS)

        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=ALL_SENDER_PORTS, rx_delay_ms=100)

        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(pg_id, stats)
        print(get_readable_latency_stats(pg_id, lat_stats))
        tx_bps_L1 = stats[TX_PORT[0]].get("tx_bps_L1", 0)
        rx_bps_L1 = stats[RX_PORT[0]].get("rx_bps_L1", 0)

        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))

        # Check that expected traffic rate can be achieved.
        assert(lat_stats.total_rx > 0), "No control traffic has been received"
        assert(
            EXPECTED_FLOW_RATE_WITH_STATS_BPS * 0.99 <= tx_bps_L1
        ), "The achieved Tx rate {} is lower than the expected Tx rate of {}".format(to_readable(tx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS))
        assert(
            EXPECTED_FLOW_RATE_WITH_STATS_BPS * 0.95 <= rx_bps_L1 <= EXPECTED_FLOW_RATE_WITH_STATS_BPS * 1.05
        ), "The measured RX rate {} is not close to the TX rate {}".format(to_readable(rx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS))
