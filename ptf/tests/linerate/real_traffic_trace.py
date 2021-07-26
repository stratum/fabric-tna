# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

from base_test import *
from fabric_test import *
from trex_test import TRexTest
from trex_utils import list_port_status
from xnt import analyze_report_pcap

TRAFFIC_SPEEDUP = 0.01
TEST_DURATION = 5
CAPTURE_LIMIT = 10000
REMOTE_PCAP_DIR = "/srv/packet-traces/CAIDA_traces_passive-2016_equinix-chicago/equinix-chicago/20160121-130000/"
REMOTE_PCAP_FILE = "equinix-chicago.dirA.20160121-130000.UTC.anon.no-fragment.pcap"
TOTAL_FLOWS = 921458 # specified in REMOTE_PCAP_DIR/130000.txt

SENDER_PORT = 0
RECEIVER_PORT = 1
INT_COLLECTOR_PORT = 2


class RealTrafficTrace(TRexTest, IntTest):
    @autocleanup
    def doRunTest(
        self,
        mult,
        tagged1,
        tagged2,
        is_device_spine,
        send_report_to_spine,
        is_next_hop_spine,
    ):

        print(f"Testing tagged1={tagged1}, tagged2={tagged2}, is_device_spine={is_device_spine}, send_report_to_spine={send_report_to_spine}, is_next_hop_spine={is_next_hop_spine}")

        # TODO: replace with set_up_ipv4_unicast_rules after Yi merge
        pkt = testutils.simple_udp_packet()
        pkt[Ether].dst = "00:90:fb:71:64:8a"
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)
        self.set_up_watchlist_flow()
        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged1,
            tagged2=tagged2,
            dst_ipv4="0.0.0.0",
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=0,
            ig_port=self.port1,
            eg_port=self.port2,
            no_send=True,
        )

        # Capture INT packets
        self.trex_client.set_service_mode(ports=[INT_COLLECTOR_PORT], enabled=True)
        capture = self.trex_client.start_capture(
            rx_ports=[INT_COLLECTOR_PORT],
            limit=CAPTURE_LIMIT
        )

        # Start sending stateless traffic
        pcap_file = REMOTE_PCAP_DIR + REMOTE_PCAP_FILE
        self.trex_client.push_remote(
            pcap_file,
            ports=[SENDER_PORT],
            speedup=mult,
            duration=TEST_DURATION
        )
        self.trex_client.wait_on_traffic(ports=[SENDER_PORT])

        output = "/tmp/real-traffic-trace-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.trex_client.stop_capture(capture["id"], output)
        analyze_report_pcap(output, TOTAL_FLOWS)

        # Check if we received each packet we sent
        port_stats = self.trex_client.get_stats()
        sent_packets = port_stats[SENDER_PORT]["opackets"]
        recv_packets = port_stats[RECEIVER_PORT]["ipackets"]
        int_packets = port_stats[INT_COLLECTOR_PORT]["ipackets"]

        print(f"Sent {sent_packets}, recv {recv_packets}, INT {int_packets}")
        self.failIf(sent_packets != recv_packets, f"Didn't receive all packets; sent {sent_packets}, received {recv_packets}")

        list_port_status(port_stats) 

        """ 
        TODO: Verify the following:
        - IRG: Received one INT report per second per flow
        - Efficiency + accuracy scores: above/below certain threshold
        """

    def runTest(self):
        # TODO: iterate all possible parameters of test with get_test_args
        self.doRunTest(TRAFFIC_SPEEDUP, False, False, False, False, False)
