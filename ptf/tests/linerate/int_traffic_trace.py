# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

from base_test import *
from fabric_test import *
from ptf.testutils import group
from trex_test import TRexTest
from trex_utils import list_port_status
from xnt import analyze_report_pcap

TRAFFIC_SPEEDUP = 1.0
TEST_DURATION = 60
CAPTURE_LIMIT = 4000000
REMOTE_PCAP_DIR = "/srv/packet-traces/CAIDA_traces_passive-2016_equinix-chicago/equinix-chicago/20160121-130000/"
REMOTE_PCAP_FILE = (
    "equinix-chicago.dirA.20160121-130000.UTC.anon.no-fragment-fix-ttl.pcap"
)
TOTAL_FLOWS = 921458  # specified in REMOTE_PCAP_DIR/130000.txt

ACCURACY_RECORD = 99.6
EFFICIENCY_RECORD = 58.3

SENDER_PORT = 0
RECEIVER_PORT = 1
INT_COLLECTOR_PORT = 2


""" 
This test performs a replay of real-time packet traffic captured from an Equinix
datacenter in Chicago through our PISA switch. The traffic capture is read and
replayed by TRex, the traffic generator used for our linerate tests.

In the capture, there are a total of 921,458 unique flows. This test observes
the behaviour of our P4 implementation of INT flow report filtering when
processing linerate traffic with this high number of flows, and thus assesses
its performance when encountering bloom filter collisions.
"""


@group("int")
class IntFlowFilterWithTrafficTrace(TRexTest, IntTest):
    @autocleanup
    def runTest(self):

        pkt = testutils.simple_udp_packet()
        self.set_up_int_flows(
            is_device_spine=False, pkt=pkt, send_report_to_spine=False
        )
        self.set_up_watchlist_flow()
        self.set_up_ipv4_unicast_rules(
            next_hop_mac=HOST2_MAC,
            ig_port=self.port1,
            eg_port=self.port2,
            dst_ipv4="0.0.0.0",
            prefix_len=0,
            switch_mac="00:90:fb:71:64:8a",  # so switch mac matches with ethernet dst of packets in pcap
        )

        # Capture INT packets
        self.trex_client.set_service_mode(ports=[INT_COLLECTOR_PORT], enabled=True)
        capture = self.trex_client.start_capture(
            rx_ports=[INT_COLLECTOR_PORT], limit=CAPTURE_LIMIT
        )

        # Start sending pcap traffic
        pcap_file = REMOTE_PCAP_DIR + REMOTE_PCAP_FILE
        self.trex_client.push_remote(
            pcap_file,
            ports=[SENDER_PORT],
            speedup=TRAFFIC_SPEEDUP,
            duration=TEST_DURATION,
        )
        self.trex_client.wait_on_traffic(ports=[SENDER_PORT])

        output = "/tmp/int-traffic-trace-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.trex_client.stop_capture(capture["id"], output)
        results = analyze_report_pcap(output, TOTAL_FLOWS)

        port_stats = self.trex_client.get_stats()
        sent_packets = port_stats[SENDER_PORT]["opackets"]
        recv_packets = port_stats[RECEIVER_PORT]["ipackets"]
        int_packets = port_stats[INT_COLLECTOR_PORT]["ipackets"]

        print(f"Sent {sent_packets}, recv {recv_packets}, INT {int_packets}")
        list_port_status(port_stats)

        """ 
        Verify the following:
        - Packet loss: Ensure 0% packet loss
        - Accuracy score: Ensure test is above a certain threshold
        - Efficiency score: Ensure efficiency remains above a certain threshold
        """
        self.failIf(
            sent_packets != recv_packets,
            f"Didn't receive all packets; sent {sent_packets}, received {recv_packets}",
        )

        accuracy_score = results["flow_accuracy_score"]
        self.failIf(
            accuracy_score < ACCURACY_RECORD,
            f"Accuracy score should be at least {ACCURACY_RECORD}%, was {accuracy_score}%",
        )

        efficiency_score = results["flow_efficiency_score"]
        self.failIf(
            efficiency_score < EFFICIENCY_RECORD,
            f"Efficiency score should be at least {EFFICIENCY_RECORD}%, was {efficiency_score}%",
        )
