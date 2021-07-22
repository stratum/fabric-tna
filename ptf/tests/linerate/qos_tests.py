# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import pprint
from argparse import ArgumentParser
from datetime import datetime

from base_test import *
from fabric_test import *
from trex_test import TRexTest
from trex_utils import *
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont, STLFlowLatencyStats
import qos_utils
import gnmi_utils

EXPECTED_FLOW_RATE_WITH_STATS_BPS = 1 * G
CONTROL_QUEUE_MAX_RATE_BPS = 60 * M
SYSTEM_QUEUE_MAX_RATE_BPS = 10 * M

TRAFFIC_DURATION_SECONDS = 10

MAXIMUM_EXPECTED_LATENCY_CONTROL_TRAFFIC_US = 1000
AVERAGE_EXPECTED_LATENCY_CONTROL_TRAFFIC_US = 500

BACKGROUND_SENDER_PORT = [0]
PRIORITY_SENDER_PORT = [2]
ALL_SENDER_PORTS = [0, 2]
RECEIVER_PORT = [1]
ALL_PORTS = [0, 1, 2]

class QosTest(TRexTest, SlicingTest):
    def __init__(self):
        super().__init__()
        self.control_pg_id = 7
        self.system_pg_id = 2

    def push_chassis_config(self) -> None:
        chassis_config = b""
        with open("../linerate/chassis_config_for_qos_strict_priority.pb.txt", mode='rb') as file:
            chassis_config = file.read()
        gnmi_utils.push_chassis_config(chassis_config)

    def setup_basic_forwarding(self) -> None:
        self.setup_port(self.port1, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port2, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port3, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port1)
        self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port3)

    def setup_queue_classification(self) -> None:
        self.add_slice_tc_classifier_entry(slice_id=1, tc=0, l4_dport=qos_utils.L4_DPORT_CONTROL_TRAFFIC)
        self.add_queue_entry(1, 0, qos_utils.QUEUE_ID_CONTROL)
        self.add_slice_tc_classifier_entry(slice_id=2, tc=0, l4_dport=qos_utils.L4_DPORT_SYSTEM_TRAFFIC)
        self.add_queue_entry(2, 0, qos_utils.QUEUE_ID_SYSTEM)

    # Create a background traffic stream.
    def create_background_stream(self) -> STLStream:
        pkt = qos_utils.get_best_effort_traffic_packet()
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(percentage=100))

    # Create a highest priority control stream.
    def create_control_stream(self, pg_id) -> STLStream:
        pkt = qos_utils.get_control_traffic_packet(128)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=CONTROL_QUEUE_MAX_RATE_BPS),
            isg=50000, # wait 50 ms till start to let queues fill up
            flow_stats = STLFlowLatencyStats(pg_id = pg_id))

    # Create a second highest priority system stream.
    def create_system_stream(self, pg_id) -> STLStream:
        pkt = qos_utils.get_system_traffic_packet()
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=SYSTEM_QUEUE_MAX_RATE_BPS),
            isg=50000, # wait 50 ms till start to let queues fill up
            flow_stats = STLFlowLatencyStats(pg_id = pg_id))


class MinFlowrateWithSoftwareLatencyMeasurement(QosTest):
    # Create a highest priority control stream.
    def create_control_stream(self, pg_id) -> STLStream:
        pkt = qos_utils.get_control_traffic_packet(64)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=EXPECTED_FLOW_RATE_WITH_STATS_BPS),
            flow_stats = STLFlowLatencyStats(pg_id = pg_id))

    @autocleanup
    def runTest(self):
        self.push_chassis_config()
        self.setup_basic_forwarding()
        # Create the control stream
        control_stream = self.create_control_stream(self.control_pg_id)
        self.trex_client.add_streams(control_stream, ports=BACKGROUND_SENDER_PORT)
        # Start sending traffic
        logging.info("Starting traffic, duration: %d sec", TRAFFIC_DURATION_SECONDS)
        self.trex_client.start(BACKGROUND_SENDER_PORT, mult='1', duration=TRAFFIC_DURATION_SECONDS)
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=BACKGROUND_SENDER_PORT, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(self.control_pg_id, stats)
        flow_stats = get_flow_stats(self.control_pg_id, stats)
        print(get_readable_latency_stats(self.control_pg_id, lat_stats))
        tx_bps_L1 = stats[BACKGROUND_SENDER_PORT[0]].get("tx_bps_L1", 0)
        rx_bps_L1 = stats[RECEIVER_PORT[0]].get("rx_bps_L1", 0)
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
        # Check that expected traffic rate can be achieved.
        self.assertGreater(flow_stats.total_rx, 0, "No control traffic has been received")
        self.assertGreaterEqual(tx_bps_L1, EXPECTED_FLOW_RATE_WITH_STATS_BPS * 0.99, "The achieved Tx rate {} is lower than the expected Tx rate of {}".format(to_readable(tx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS)))
        self.assertGreaterEqual(rx_bps_L1, EXPECTED_FLOW_RATE_WITH_STATS_BPS * 0.95, "The measured RX rate {} is lower than the expected TX rate {}".format(to_readable(rx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS)))
        self.assertLessEqual(rx_bps_L1, EXPECTED_FLOW_RATE_WITH_STATS_BPS * 1.05, "The measured RX rate {} is higher than the expected TX rate {}".format(to_readable(rx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS)))


class StrictPriorityControlTrafficIsPrioritized(QosTest):
    @autocleanup
    def runTest(self) -> None:
        self.push_chassis_config()
        self.setup_basic_forwarding()
        self.setup_queue_classification()
        # Create a background traffic stream
        background_stream = self.create_background_stream()
        self.trex_client.add_streams(background_stream, ports=BACKGROUND_SENDER_PORT)
        # Create the control stream
        control_stream = self.create_control_stream(self.control_pg_id)
        self.trex_client.add_streams(control_stream, ports=PRIORITY_SENDER_PORT)
        # Create the system stream
        system_stream = self.create_system_stream(self.system_pg_id)
        self.trex_client.add_streams(system_stream, ports=PRIORITY_SENDER_PORT)
        # Start sending traffic
        logging.info("Starting traffic, duration: %d sec", TRAFFIC_DURATION_SECONDS)
        self.trex_client.start(ALL_SENDER_PORTS, mult='1', duration=TRAFFIC_DURATION_SECONDS)
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=ALL_SENDER_PORTS, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(self.control_pg_id, stats)
        flow_stats = get_flow_stats(self.control_pg_id, stats)
        print(get_readable_latency_stats(self.control_pg_id, lat_stats))
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
        # Check that SLAs are met.
        self.assertGreater(flow_stats.total_rx, 0, "No control traffic has been received")
        self.assertEqual(lat_stats.dropped, 0, f"Control traffic has been dropped: {lat_stats.dropped}")
        self.assertEqual(lat_stats.seq_too_high, 0, f"Control traffic has been dropped or reordered: {lat_stats.seq_too_high}")
        self.assertEqual(lat_stats.seq_too_low, 0, f"Control traffic has been dropped or reordered: {lat_stats.seq_too_low}")
        self.assertLessEqual(lat_stats.total_max, MAXIMUM_EXPECTED_LATENCY_CONTROL_TRAFFIC_US, f"Maximum latency in control traffic is too high: {lat_stats.total_max}")
        self.assertLessEqual(lat_stats.average, AVERAGE_EXPECTED_LATENCY_CONTROL_TRAFFIC_US, f"Average latency in control traffic is too high: {lat_stats.average}")


class StrictPriorityCounterCheck(QosTest):
    @autocleanup
    def runTest(self) -> None:
        self.push_chassis_config()
        self.setup_basic_forwarding()
        # Create a background traffic stream
        background_stream = self.create_background_stream()
        self.trex_client.add_streams(background_stream, ports=BACKGROUND_SENDER_PORT)
        # Create the control stream
        control_stream = self.create_control_stream(self.control_pg_id)
        self.trex_client.add_streams(control_stream, ports=PRIORITY_SENDER_PORT)
        # Create the system stream
        system_stream = self.create_system_stream(self.system_pg_id)
        self.trex_client.add_streams(system_stream, ports=PRIORITY_SENDER_PORT)
        # Start sending traffic
        logging.info("Starting traffic, duration: %d sec", TRAFFIC_DURATION_SECONDS)
        self.trex_client.start(ALL_SENDER_PORTS, mult='1', duration=TRAFFIC_DURATION_SECONDS)
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=ALL_SENDER_PORTS, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(self.control_pg_id, stats)
        flow_stats = get_flow_stats(self.control_pg_id, stats)
        print(get_readable_latency_stats(self.control_pg_id, lat_stats))
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
        # Check that SLAs are NOT met.
        self.assertGreater(flow_stats.total_rx, 0, "No control traffic has been received")
        self.assertGreater(lat_stats.dropped, 0, f"Control traffic has not been dropped: {lat_stats.dropped}")
        self.assertGreater(lat_stats.seq_too_high + lat_stats.seq_too_low, 0, f"Control traffic has not been dropped or reordered: sequence to high {lat_stats.seq_too_high}, sequence to low {lat_stats.seq_too_low}")
        self.assertGreaterEqual(lat_stats.total_max, MAXIMUM_EXPECTED_LATENCY_CONTROL_TRAFFIC_US, f"Maximum latency in control traffic is not over the expected limit: {lat_stats.total_max}")
        self.assertGreaterEqual(lat_stats.average, AVERAGE_EXPECTED_LATENCY_CONTROL_TRAFFIC_US, f"Average latency in control traffic not over the expected limit: {lat_stats.average}")
