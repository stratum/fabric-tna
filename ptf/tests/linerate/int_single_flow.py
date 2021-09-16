# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

from base_test import *
from fabric_test import *
from ptf.testutils import group
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest
from trex_utils import list_port_status

TRAFFIC_MULT = "40gbpsl1"
TEST_DURATION = 10
CAPTURE_LIMIT = 20

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

        self.pypy_parse_pcap(output)
        port_stats = self.trex_client.get_stats()

        sent_packets = port_stats[SENDER_PORT]["opackets"]
        recv_packets = port_stats[RECEIVER_PORT]["ipackets"]

        list_port_status(port_stats)

        self.failIf(
            sent_packets != recv_packets,
            f"Didn't receive all packets; sent {sent_packets}, received {recv_packets}",
        )

    def runTest(self):
        # TODO: iterate all possible parameters of test
        pkt = testutils.simple_udp_packet()
        self.doRunTest(TRAFFIC_MULT, pkt, [False, False], False, False, False)
