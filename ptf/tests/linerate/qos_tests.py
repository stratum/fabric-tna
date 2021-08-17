# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

# This file contains line rate tests checking that our QoS targets are
# satisfied. For more information, see this doc:
# https://docs.google.com/document/d/1jq6NH-fffe8ImMo4EC_yMwH1djlrhWaQu2lpLFJKljA

import logging

from ptf.testutils import group

import gnmi_utils
import qos_utils
import yaml
from base_test import *
from fabric_test import *
from stratum_qos_config import vendor_config
from trex_stl_lib.api import STLFlowLatencyStats, STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest
from trex_utils import *

# General test parameter.
LINK_RATE_BPS = 1 * G
EXPECTED_FLOW_RATE_WITH_STATS_BPS = 1 * G
TRAFFIC_DURATION_SECONDS = 10

# Maximum queue rates as per ChassisConfig.
CONTROL_QUEUE_MAX_RATE_BPS = 60 * M
REALTIME_1_QUEUE_MAX_RATE_BPS = 45 * M
REALTIME_2_QUEUE_MAX_RATE_BPS = 30 * M
REALTIME_3_QUEUE_MAX_RATE_BPS = 25 * M
SYSTEM_QUEUE_MAX_RATE_BPS = 10 * M

# Latency expectations for various traffic types in microseconds.
EXPECTED_MAXIMUM_LATENCY_CONTROL_TRAFFIC_US = 1000
EXPECTED_AVERAGE_LATENCY_CONTROL_TRAFFIC_US = 500
EXPECTED_99_9_PERCENTILE_LATENCY_CONTROL_TRAFFIC_US = 100
EXPECTED_MAXIMUM_LATENCY_REALTIME_TRAFFIC_US = 1500
EXPECTED_AVERAGE_LATENCY_REALTIME_TRAFFIC_US = 500
EXPECTED_99_9_PERCENTILE_LATENCY_REALTIME_TRAFFIC_US = 100

# Port setup.
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

    def push_chassis_config(self, yaml_file="qos-config-1g.yml") -> None:
        with open("../linerate/chassis_config.pb.txt", mode="rb") as file:
            chassis_config = file.read()
        # Auto-generate and append vendor_config
        with open(f"../linerate/{yaml_file}", "r") as file:
            chassis_config += bytes("\n" + vendor_config(yaml.safe_load(file)), encoding="utf8")
        # Write to disk for debugging
        with open("../linerate/chassis_config.pb.txt.tmp", mode="wb") as file:
            file.write(chassis_config)
        gnmi_utils.push_chassis_config(chassis_config)

    def setup_basic_forwarding(self) -> None:
        self.setup_port(self.port1, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port2, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port3, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port1)
        self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port3)

    def setup_queue_classification(self) -> None:
        self.add_slice_tc_classifier_entry(
            slice_id=1, tc=0, l4_dport=qos_utils.L4_DPORT_CONTROL_TRAFFIC
        )
        self.add_queue_entry(1, 0, qos_utils.QUEUE_ID_CONTROL)
        self.add_slice_tc_classifier_entry(
            slice_id=2, tc=0, l4_dport=qos_utils.L4_DPORT_SYSTEM_TRAFFIC
        )
        self.add_queue_entry(2, 0, qos_utils.QUEUE_ID_SYSTEM)
        self.add_slice_tc_classifier_entry(
            slice_id=10, tc=0, l4_dport=qos_utils.L4_DPORT_REALTIME_TRAFFIC_1
        )
        self.add_slice_tc_classifier_entry(
            slice_id=11, tc=0, l4_dport=qos_utils.L4_DPORT_REALTIME_TRAFFIC_2
        )
        self.add_slice_tc_classifier_entry(
            slice_id=12, tc=0, l4_dport=qos_utils.L4_DPORT_REALTIME_TRAFFIC_3
        )
        self.add_queue_entry(10, 0, qos_utils.QUEUE_ID_REALTIME_1)
        self.add_queue_entry(11, 0, qos_utils.QUEUE_ID_REALTIME_2)
        self.add_queue_entry(12, 0, qos_utils.QUEUE_ID_REALTIME_3)

    # Create a background traffic stream.
    def create_background_stream(self) -> STLStream:
        pkt = qos_utils.get_best_effort_traffic_packet()
        return STLStream(packet=STLPktBuilder(pkt=pkt), mode=STLTXCont(percentage=100))

    # Create a highest priority control stream.
    def create_control_stream(
        self, pg_id, l1_bps=CONTROL_QUEUE_MAX_RATE_BPS
    ) -> STLStream:
        pkt = qos_utils.get_control_traffic_packet(128)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=l1_bps),
            isg=50000,  # wait 50 ms till start to let queues fill up
            flow_stats=STLFlowLatencyStats(pg_id=pg_id),
        )

    # Create a highest priority control stream.
    def create_realtime_stream(
        self,
        pg_id,
        l1_bps=REALTIME_1_QUEUE_MAX_RATE_BPS,
        dport=qos_utils.L4_DPORT_REALTIME_TRAFFIC_1,
    ) -> STLStream:
        pkt = qos_utils.get_realtime_traffic_packet(128, dport=dport)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=l1_bps),
            isg=50000,  # wait 50 ms till start to let queues fill up
            flow_stats=STLFlowLatencyStats(pg_id=pg_id),
        )

    # Create a lower priority best-effort stream.
    def create_best_effort_stream(
            self,
            pg_id,
            dport=None,
            l2_size=None,
            l1_bps=None,
            l2_bps=None,
    ) -> STLStream:
        pkt = qos_utils.get_best_effort_traffic_packet(l2_size=l2_size, dport=dport)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=l1_bps, bps_L2=l2_bps),
            flow_stats=STLFlowLatencyStats(pg_id=pg_id),
        )

    # Create a second highest priority system stream.
    def create_system_stream(self, pg_id) -> STLStream:
        pkt = qos_utils.get_system_traffic_packet()
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=SYSTEM_QUEUE_MAX_RATE_BPS),
            isg=50000,  # wait 50 ms till start to let queues fill up
            flow_stats=STLFlowLatencyStats(pg_id=pg_id),
        )


# Not executed by default, requires running Trex in SW mode:
#   TREX_PARAMS="--trex-sw-mode" ./ptf/run/hw/linerate fabric TEST=qos_tests.FlowCountersSanityTest
@group("trex-sw-mode")
class FlowCountersSanityTest(QosTest, StatsTest):
    """
    This test ensures that switch-maintained P4 counters work as expected by
    comparing them with the Trex per-flow stats. Trex per-flow stats require
    disabling NIC HW acceleration, which might limit the ability to analyze
    traffic at high rates. To avoid having to worry about the impact of Trex
    SW-based processing on QoS tests, we prefer to keep NW acceleration enabled
    for all other tests. This test serves as a guarantee that the switch P4
    counters can be reliably used reliably in place of Trex per-flow stats.
    """

    @autocleanup
    def runTest(self) -> None:
        self.push_chassis_config()
        self.setup_basic_forwarding()

        # Create multiple streams, each one sending at the link rate..
        stream_bps = LINK_RATE_BPS
        pg_id_1 = 1
        pg_id_2 = 2
        pg_id_3 = 3
        dport_1 = 100
        dport_2 = 200
        dport_3 = 300

        streams = [
            self.create_best_effort_stream(
                pg_id=pg_id_1,
                l2_bps=stream_bps,
                dport=dport_1,
                l2_size=1400
            ),
            self.create_best_effort_stream(
                pg_id=pg_id_2,
                l2_bps=stream_bps,
                dport=dport_2,
                l2_size=1400
            ),
            self.create_best_effort_stream(
                pg_id=pg_id_3,
                l2_bps=stream_bps,
                dport=dport_3,
                l2_size=1400
            ),
        ]

        switch_ig_port = self.port3
        switch_eg_port = self.port2

        self.set_up_stats_flows(
            stats_flow_id=pg_id_1,
            ig_port=switch_ig_port,
            eg_port=switch_eg_port,
            l4_dport=dport_1,
        )
        self.set_up_stats_flows(
            stats_flow_id=pg_id_2,
            ig_port=switch_ig_port,
            eg_port=switch_eg_port,
            l4_dport=dport_2,
        )
        self.set_up_stats_flows(
            stats_flow_id=pg_id_3,
            ig_port=switch_ig_port,
            eg_port=switch_eg_port,
            l4_dport=dport_3,
        )

        self.trex_client.add_streams(streams, ports=PRIORITY_SENDER_PORT)
        self.trex_client.start(
            PRIORITY_SENDER_PORT, mult="1", duration=TRAFFIC_DURATION_SECONDS
        )
        self.trex_client.wait_on_traffic(ports=PRIORITY_SENDER_PORT, rx_delay_ms=100)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()

        flow_stats_1 = get_flow_stats(pg_id_1, trex_stats)
        print(get_readable_flow_stats(flow_stats_1))
        flow_stats_2 = get_flow_stats(pg_id_2, trex_stats)
        print(get_readable_flow_stats(flow_stats_2))
        flow_stats_3 = get_flow_stats(pg_id_3, trex_stats)
        print(get_readable_flow_stats(flow_stats_3))

        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(trex_stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))

        # Get switch stats
        ig_bytes_1, ig_packets_1 = self.get_stats_counter(
            gress=STATS_INGRESS,
            stats_flow_id=pg_id_1,
            port=switch_ig_port,
            l4_dport=dport_1)
        ig_bytes_2, ig_packets_2 = self.get_stats_counter(
            gress=STATS_INGRESS,
            stats_flow_id=pg_id_2,
            port=switch_ig_port,
            l4_dport=dport_2)
        ig_bytes_3, ig_packets_3 = self.get_stats_counter(
            gress=STATS_INGRESS,
            stats_flow_id=pg_id_3,
            port=switch_ig_port,
            l4_dport=dport_3)

        eg_bytes_1, eg_packets_1 = self.get_stats_counter(
            gress=STATS_EGRESS,
            stats_flow_id=pg_id_1,
            port=switch_eg_port,
            l4_dport=dport_1)
        eg_bytes_2, eg_packets_2 = self.get_stats_counter(
            gress=STATS_EGRESS,
            stats_flow_id=pg_id_2,
            port=switch_eg_port,
            l4_dport=dport_2)
        eg_bytes_3, eg_packets_3 = self.get_stats_counter(
            gress=STATS_EGRESS,
            stats_flow_id=pg_id_3,
            port=switch_eg_port,
            l4_dport=dport_3)

        # Compare Trex TX stats with the switch ingress counters
        self.assertEqual(flow_stats_1.tx_packets, ig_packets_1)
        self.assertEqual(flow_stats_2.tx_packets, ig_packets_2)
        self.assertEqual(flow_stats_3.tx_packets, ig_packets_3)
        self.assertEqual(flow_stats_1.tx_bytes, ig_bytes_1)
        self.assertEqual(flow_stats_2.tx_bytes, ig_bytes_2)
        self.assertEqual(flow_stats_3.tx_bytes, ig_bytes_3)

        # Compare Trex RX stats with the switch egress counters
        self.assertEqual(flow_stats_1.rx_packets, eg_packets_1)
        self.assertEqual(flow_stats_2.rx_packets, eg_packets_2)
        self.assertEqual(flow_stats_3.rx_packets, eg_packets_3)

        # Switch egress bytes count will include bridged metadata, we need to subtract
        # that before comparing with the Trex counters.
        output_bytes_1 = eg_bytes_1 - eg_packets_1 * BMD_BYTES
        output_bytes_2 = eg_bytes_2 - eg_packets_2 * BMD_BYTES
        output_bytes_3 = eg_bytes_3 - eg_packets_3 * BMD_BYTES

        self.assertEqual(flow_stats_1.rx_bytes, output_bytes_1)
        self.assertEqual(flow_stats_2.rx_bytes, output_bytes_2)
        self.assertEqual(flow_stats_3.rx_bytes, output_bytes_3)


class MinFlowrateWithSoftwareLatencyMeasurement(QosTest):
    # Create a highest priority control stream.
    def create_control_stream(self, pg_id) -> STLStream:
        pkt = qos_utils.get_control_traffic_packet(64)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=EXPECTED_FLOW_RATE_WITH_STATS_BPS),
            flow_stats=STLFlowLatencyStats(pg_id=pg_id),
        )

    @autocleanup
    def runTest(self):
        self.push_chassis_config()
        self.setup_basic_forwarding()
        # Create the control stream
        control_stream = self.create_control_stream(self.control_pg_id)
        self.trex_client.add_streams(control_stream, ports=BACKGROUND_SENDER_PORT)
        # Start sending traffic
        logging.info("Starting traffic, duration: %d sec", TRAFFIC_DURATION_SECONDS)
        self.trex_client.start(
            BACKGROUND_SENDER_PORT, mult="1", duration=TRAFFIC_DURATION_SECONDS
        )
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=BACKGROUND_SENDER_PORT, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(self.control_pg_id, stats)
        flow_stats = get_flow_stats(self.control_pg_id, stats)
        print(get_readable_latency_stats(lat_stats))
        tx_bps_L1 = stats[BACKGROUND_SENDER_PORT[0]].get("tx_bps_L1", 0)
        rx_bps_L1 = stats[RECEIVER_PORT[0]].get("rx_bps_L1", 0)
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
        # Check that expected traffic rate can be achieved.
        self.assertGreater(
            flow_stats.rx_packets, 0, "No control traffic has been received"
        )
        self.assertGreaterEqual(
            tx_bps_L1,
            EXPECTED_FLOW_RATE_WITH_STATS_BPS * 0.99,
            "The achieved Tx rate {} is lower than the expected Tx rate of {}".format(
                to_readable(tx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS)
            ),
        )
        self.assertGreaterEqual(
            rx_bps_L1,
            EXPECTED_FLOW_RATE_WITH_STATS_BPS * 0.95,
            "The measured RX rate {} is lower than the expected TX rate {}".format(
                to_readable(rx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS)
            ),
        )
        self.assertLessEqual(
            rx_bps_L1,
            EXPECTED_FLOW_RATE_WITH_STATS_BPS * 1.05,
            "The measured RX rate {} is higher than the expected TX rate {}".format(
                to_readable(rx_bps_L1), to_readable(EXPECTED_FLOW_RATE_WITH_STATS_BPS)
            ),
        )


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
        self.trex_client.start(
            ALL_SENDER_PORTS, mult="1", duration=TRAFFIC_DURATION_SECONDS
        )
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=ALL_SENDER_PORTS, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(self.control_pg_id, stats)
        flow_stats = get_flow_stats(self.control_pg_id, stats)
        print(get_readable_latency_stats(lat_stats))
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
        # Check that SLAs are met.
        self.assertGreater(
            flow_stats.rx_packets, 0, "No control traffic has been received"
        )
        self.assertEqual(
            lat_stats.dropped,
            0,
            f"Control traffic has been dropped: {lat_stats.dropped}",
        )
        self.assertEqual(
            lat_stats.seq_too_high,
            0,
            f"Control traffic has been dropped or reordered: {lat_stats.seq_too_high}",
        )
        self.assertEqual(
            lat_stats.seq_too_low,
            0,
            f"Control traffic has been dropped or reordered: {lat_stats.seq_too_low}",
        )
        self.assertLessEqual(
            lat_stats.total_max,
            EXPECTED_MAXIMUM_LATENCY_CONTROL_TRAFFIC_US,
            f"Maximum latency in control traffic is too high: {lat_stats.total_max}",
        )
        self.assertLessEqual(
            lat_stats.percentile_99_9,
            EXPECTED_99_9_PERCENTILE_LATENCY_CONTROL_TRAFFIC_US,
            f"99.9th percentile latency in control traffic is too high: {lat_stats.percentile_99_9}",
        )


class ControlTrafficIsNotPrioritizedWithoutRules(QosTest):
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
        self.trex_client.start(
            ALL_SENDER_PORTS, mult="1", duration=TRAFFIC_DURATION_SECONDS
        )
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=ALL_SENDER_PORTS, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(self.control_pg_id, stats)
        flow_stats = get_flow_stats(self.control_pg_id, stats)
        print(get_readable_latency_stats(lat_stats))
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
        # Check that SLAs are NOT met.
        self.assertGreater(
            flow_stats.rx_packets, 0, "No control traffic has been received"
        )
        self.assertGreater(
            lat_stats.dropped,
            0,
            f"Control traffic has not been dropped: {lat_stats.dropped}",
        )
        self.assertGreater(
            lat_stats.seq_too_high + lat_stats.seq_too_low,
            0,
            f"Control traffic has not been dropped or reordered: sequence to high {lat_stats.seq_too_high}, sequence to low {lat_stats.seq_too_low}",
        )
        self.assertGreaterEqual(
            lat_stats.total_max,
            EXPECTED_MAXIMUM_LATENCY_CONTROL_TRAFFIC_US,
            f"Maximum latency in control traffic is not over the expected limit: {lat_stats.total_max}",
        )
        self.assertGreaterEqual(
            lat_stats.percentile_99_9,
            EXPECTED_99_9_PERCENTILE_LATENCY_CONTROL_TRAFFIC_US,
            f"99.9th percentile latency in control traffic not over the expected limit: {lat_stats.percentile_99_9}",
        )


class ControlTrafficIsShaped(QosTest):
    @autocleanup
    def runTest(self) -> None:
        self.push_chassis_config()
        self.setup_basic_forwarding()
        self.setup_queue_classification()
        # Create the control stream with above maximum allocated rate
        control_stream = self.create_control_stream(
            self.control_pg_id, CONTROL_QUEUE_MAX_RATE_BPS * 1.1
        )
        self.trex_client.add_streams(control_stream, ports=PRIORITY_SENDER_PORT)
        # Start sending traffic
        logging.info("Starting traffic, duration: %d sec", TRAFFIC_DURATION_SECONDS)
        self.trex_client.start(
            PRIORITY_SENDER_PORT, mult="1", duration=TRAFFIC_DURATION_SECONDS
        )
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=PRIORITY_SENDER_PORT, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        lat_stats = get_latency_stats(self.control_pg_id, stats)
        flow_stats = get_flow_stats(self.control_pg_id, stats)
        rx_port_stats = get_port_stats(RECEIVER_PORT[0], stats)
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
        # Check that rate limits are enforced.
        self.assertGreater(
            flow_stats.rx_packets, 0, "No control traffic has been received"
        )
        self.assertGreater(
            lat_stats.dropped,
            0,
            f"Control traffic has not been dropped: {lat_stats.dropped}",
        )
        self.assertLessEqual(
            rx_port_stats.rx_bps_L1,
            CONTROL_QUEUE_MAX_RATE_BPS * 1.01,  # allow small marging of error
            f"Control traffic has not been rate limtied: {rx_port_stats.rx_bps_L1}",
        )
        self.assertGreaterEqual(
            lat_stats.total_max,
            EXPECTED_MAXIMUM_LATENCY_CONTROL_TRAFFIC_US,
            f"Maximum latency in control traffic is not over the expected limit: {lat_stats.total_max}",
        )
        self.assertGreaterEqual(
            lat_stats.percentile_99_9,
            EXPECTED_99_9_PERCENTILE_LATENCY_CONTROL_TRAFFIC_US,
            f"99.9th percentile latency in control traffic not over the expected limit: {lat_stats.percentile_99_9}",
        )


class RealtimeTrafficIsRrScheduled(QosTest):
    """
    In this test we check that well behaved realtime traffic is not negatively
    impacted by other realtime flows that are not. For this we start 3 streams
    and assign them to separate queues. Stream 1 and 2 will send more than their
    alloted rate, while stream 3 is within limits. We expect that stream 3 will
    experience the lowest latency and no packet drops, while the other streams should.
    """

    @autocleanup
    def runTest(self) -> None:
        self.realtime_pg_id_1 = 1
        self.realtime_pg_id_2 = 2
        self.realtime_pg_id_3 = 3
        self.push_chassis_config()
        self.setup_basic_forwarding()
        self.setup_queue_classification()
        # Create multiple realtime streams. Stream 1 and 2 send more than the
        # alloted rate, while stream 3 is well behaved.
        rt_streams = [
            self.create_realtime_stream(
                self.realtime_pg_id_1,
                l1_bps=REALTIME_1_QUEUE_MAX_RATE_BPS * 1.1,
                dport=qos_utils.L4_DPORT_REALTIME_TRAFFIC_1,
            ),
            self.create_realtime_stream(
                self.realtime_pg_id_2,
                l1_bps=REALTIME_2_QUEUE_MAX_RATE_BPS * 1.1,
                dport=qos_utils.L4_DPORT_REALTIME_TRAFFIC_2,
            ),
            self.create_realtime_stream(
                self.realtime_pg_id_3,
                l1_bps=REALTIME_3_QUEUE_MAX_RATE_BPS * 1.0,
                dport=qos_utils.L4_DPORT_REALTIME_TRAFFIC_3,
            ),
        ]
        self.trex_client.add_streams(rt_streams, ports=PRIORITY_SENDER_PORT)
        # Start sending traffic
        logging.info("Starting traffic, duration: %d sec", TRAFFIC_DURATION_SECONDS)
        self.trex_client.start(
            PRIORITY_SENDER_PORT, mult="1", duration=TRAFFIC_DURATION_SECONDS
        )
        logging.info("Waiting until all traffic is sent")
        self.trex_client.wait_on_traffic(ports=PRIORITY_SENDER_PORT, rx_delay_ms=100)
        # Get latency stats
        stats = self.trex_client.get_stats()
        # Check RT stream 1
        lat_stats_1 = get_latency_stats(self.realtime_pg_id_1, stats)
        flow_stats_1 = get_flow_stats(self.realtime_pg_id_1, stats)
        print(get_readable_latency_stats(lat_stats_1))
        self.assertGreater(
            flow_stats_1.rx_packets, 0, "No realtime traffic has been received"
        )
        self.assertGreater(
            lat_stats_1.dropped,
            0,
            f"Non-compliant realtime traffic has not been dropped: {lat_stats_1.dropped}",
        )
        self.assertGreaterEqual(
            lat_stats_1.total_max,
            EXPECTED_MAXIMUM_LATENCY_REALTIME_TRAFFIC_US,
            f"Maximum latency in realtime traffic is not over the expected limit: {lat_stats_1.total_max}",
        )
        self.assertGreaterEqual(
            lat_stats_1.percentile_99_9,
            EXPECTED_99_9_PERCENTILE_LATENCY_REALTIME_TRAFFIC_US,
            f"99.9th percentile latency in realtime traffic is is not over the expected limit: {lat_stats_1.percentile_99_9}",
        )
        # Check RT stream 2
        lat_stats_2 = get_latency_stats(self.realtime_pg_id_2, stats)
        flow_stats_2 = get_flow_stats(self.realtime_pg_id_2, stats)
        print(get_readable_latency_stats(lat_stats_2))
        self.assertGreater(
            flow_stats_2.rx_packets, 0, "No realtime traffic has been received"
        )
        self.assertGreater(
            lat_stats_2.dropped,
            0,
            f"Non-compliant realtime traffic has not been dropped: {lat_stats_2.dropped}",
        )
        self.assertGreaterEqual(
            lat_stats_2.total_max,
            EXPECTED_MAXIMUM_LATENCY_REALTIME_TRAFFIC_US,
            f"Maximum latency in control traffic is not over the expected limit: {lat_stats_2.total_max}",
        )
        self.assertGreaterEqual(
            lat_stats_2.percentile_99_9,
            EXPECTED_99_9_PERCENTILE_LATENCY_REALTIME_TRAFFIC_US,
            f"99.9th percentile latency in realtime traffic is is not over the expected limit: {lat_stats_2.percentile_99_9}",
        )
        # Check RT stream 3
        lat_stats_3 = get_latency_stats(self.realtime_pg_id_3, stats)
        flow_stats_3 = get_flow_stats(self.realtime_pg_id_3, stats)
        print(get_readable_latency_stats(lat_stats_3))
        self.assertGreater(
            flow_stats_3.rx_packets, 0, "No realtime traffic has been received"
        )
        self.assertEqual(
            lat_stats_3.dropped,
            0,
            f"Realtime traffic has been dropped: {lat_stats_3.dropped}",
        )
        self.assertLessEqual(
            lat_stats_3.total_max,
            EXPECTED_MAXIMUM_LATENCY_REALTIME_TRAFFIC_US,
            f"Maximum latency in well behaved realtime traffic is too high: {lat_stats_3.total_max}",
        )
        self.assertLessEqual(
            lat_stats_3.percentile_99_9,
            EXPECTED_99_9_PERCENTILE_LATENCY_REALTIME_TRAFFIC_US,
            f"99th percentile latency in well behaved realtime traffic is too high: {lat_stats_3.percentile_99_9}",
        )
        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))
