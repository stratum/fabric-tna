# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

from base_test import *
from fabric_test import *
from ptf.testutils import group
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest
from trex_utils import list_port_status
from xnt import pypy_analyze_int_report_pcap

TRAFFIC_MULT = "40gbpsl1"
TEST_DURATION = 10
CAPTURE_LIMIT = 30

MIN_FLOW_REPORTS = 28

SENDER_PORT = 0
RECEIVER_PORT = 1
INT_COLLECTOR_PORT = 2


@group("int")
class IntSingleFlow(TRexTest, IntTest):
    @autocleanup
    def doRunTest(
        self,
        mult,
        pkt,
        tagged,
        is_device_spine,
        send_report_to_spine,
        is_next_hop_spine,
    ):

        # Install routing flows onto hardware switch
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)
        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            with_another_pkt_later=True,
            ig_port=self.port1,
            eg_port=self.port2,
            no_send=True,
        )

        # Define traffic to be sent
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())
        self.trex_client.add_streams(stream, ports=[SENDER_PORT])

        # Capture INT packets
        self.trex_client.set_service_mode(ports=[INT_COLLECTOR_PORT], enabled=True)
        capture = self.trex_client.start_capture(
            rx_ports=[INT_COLLECTOR_PORT],
            limit=CAPTURE_LIMIT,
            bpf_filter="udp and dst port 32766",
        )

        # Start sending stateless traffic
        self.trex_client.start(ports=[SENDER_PORT], mult=mult, duration=TEST_DURATION)
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
        - INT reports: 1 INT report per second per flow was generated
        """
        self.failIf(
            sent_packets != recv_packets,
            f"Didn't receive all packets; sent {sent_packets}, received {recv_packets}",
        )

        """
        Although duration is 10, test in reality runs for 29-30 seconds. Since
        one INT report is generated each second for each flow, and this test has
        one flow, the expected number of flow reports generated should be at
        least 28.
        """
        local_reports = results["local_reports"]
        self.failIf(
            local_reports < MIN_FLOW_REPORTS,
            f"Flow reports generated for ~30 second test should be at least 28, was {local_reports}",
        )

    def runTest(self):
        # TODO: iterate all possible parameters of test
        pkt = testutils.simple_udp_packet()
        self.doRunTest(TRAFFIC_MULT, pkt, [False, False], False, False, False)
