# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

from base_test import *
from fabric_test import *
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest
from xnt import analyze_report_pcap

TRAFFIC_MULT = 1 # 1x speed
TEST_DURATION = 10
CAPTURE_LIMIT = 1000
TOTAL_FLOWS = 0
REMOTE_PCAP_DIR = "/srv/packet-traces/CAIDA_traces_passive-2016_equinix-chicago/equinix-chicago/20160121-130000/"
REMOTE_PCAP_FILE = "equinix-chicago.dirA.20160121-130000.UTC.anon.no-fragment.pcap"

SENDER_PORT = 0
RECEIVER_PORT = 2
INT_COLLECTOR_PORT = 3


class RealTrafficTrace(TRexTest, IntTest):
    @autocleanup
    def doRunTest(self, mult, tagged1, tagged2, is_device_spine, send_report_to_spine, is_next_hop_spine):
        print(f"Testing tagged1={tagged1}, tagged2={tagged2}, is_device_spine={is_device_spine}, send_report_to_spine={send_report_to_spine}, is_next_hop_spine={is_next_hop_spine}")
        self.trex_client.reset()  # Resets configs from all ports
        self.trex_client.clear_stats()  # Clear status from all ports

        # TODO: replace with set_up_ipv4_unicast_rules after Yi merge
        pkt = testutils.simple_udp_packet()
        pkt[Ether].dst = "00:90:fb:71:64:8a"
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)
        self.set_up_watchlist_flow(pkt[IP].src, pkt[IP].dst, pkt[UDP].src, pkt[UDP].dst)
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

        # Put RX ports to promiscuous mode, otherwise it will drop all packets if the
        # destination mac is not the port mac address.
        # TODO: change based on port decision
        self.trex_client.set_port_attr(
            [INT_COLLECTOR_PORT, RECEIVER_PORT], promiscuous=True
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
            ipg_usec=100,
            speedup=mult,
            duration=TEST_DURATION,
            src_mac_pcap=True,
            dst_mac_pcap=False
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
        self.failIf(sent_packets != recv_packets, f"Didn't receive all packets; sent {sent_packets}, received {recv_packets}")


        """ 
        TODO: Verify the following:
        - IRG: Received one INT report per second per flow
        - Efficiency + accuracy scores: above/below certain threshold
        """

    def runTest(self):
        # TODO: iterate all possible parameters of test with get_test_args
        self.doRunTest(TRAFFIC_MULT, False, False, False, False, False)
