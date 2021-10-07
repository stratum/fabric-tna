# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

from base_test import *
from fabric_test import *
from ptf.testutils import group
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest
from trex_utils import *
from xnt import pypy_analyze_int_report_pcap

TRAFFIC_MULT = "1"
RATE = 40_000_000_000  # 40 Gbps
TEST_DURATION = 10
CAPTURE_LIMIT = 30

EXPECTED_FLOW_REPORTS = 10

SENDER_PORT = 0
RECEIVER_PORT = 1
INT_COLLECTOR_PORT = 2


@group("int")
class IntSingleFlow(TRexTest, IntTest):
    @autocleanup
    def runTest(self):
        self.push_chassis_config()

        pkt = testutils.simple_udp_packet(pktlen=1400)

        # Install routing flows onto hardware switch
        self.set_up_int_flows(
            is_device_spine=False, pkt=pkt, send_report_to_spine=False
        )
        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=False,
            tagged2=False,
            is_next_hop_spine=False,
            prefix_len=32,
            with_another_pkt_later=True,
            ig_port=self.port1,
            eg_port=self.port2,
            no_send=True,
        )

        # Define traffic to be sent
        stream = STLStream(
            packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont(bps_L1=RATE)
        )
        self.trex_client.add_streams(stream, ports=[SENDER_PORT])

        # Capture INT packets
        self.trex_client.set_service_mode(ports=[INT_COLLECTOR_PORT], enabled=True)
        capture = self.trex_client.start_capture(
            rx_ports=[INT_COLLECTOR_PORT],
            limit=CAPTURE_LIMIT,
            bpf_filter="udp and dst port 32766",
        )

        # Start sending stateless traffic
        self.trex_client.start(
            ports=[SENDER_PORT], mult=TRAFFIC_MULT, duration=TEST_DURATION
        )
        self.trex_client.wait_on_traffic(ports=[SENDER_PORT])

        output = "/tmp/int-single-flow-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.trex_client.stop_capture(capture["id"], output)

        results = pypy_analyze_int_report_pcap(output)
        port_stats = self.trex_client.get_stats()

        sent_packets = port_stats[SENDER_PORT]["opackets"]
        recv_packets = port_stats[RECEIVER_PORT]["ipackets"]

        list_port_status(port_stats)

        """
        Verify the following:
        - Packet loss: No packets were dropped during the test
        - Reports: 1 INT report per second per flow was generated
        """
        self.assertEqual(
            sent_packets,
            recv_packets,
            f"Didn't receive all packets; sent {sent_packets}, received {recv_packets}",
        )

        local_reports = results["local_reports"]
        self.assertTrue(
            local_reports in [EXPECTED_FLOW_REPORTS, 11],
            f"Flow reports generated for 10 second single flow test should be 10 or 11, was {local_reports}",
        )
