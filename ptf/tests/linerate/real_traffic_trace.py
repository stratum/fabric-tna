# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

from base_test import *
from fabric_test import *
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest
from trex_utils import list_port_status
from xnt import analyze_report_pcap

TRAFFIC_MULT = 1
TEST_DURATION = 10
CAPTURE_LIMIT = 1000
TOTAL_FLOWS = 0
REMOTE_PCAP_DIR = "/srv/packet-traces/CAIDA_traces_passive-2016_equinix-chicago/equinix-chicago/20160121-130000/"
REMOTE_PCAP_FILE = "equinix-chicago.dirA.20160121-130000.UTC.anon.no-fragment.pcap"

SENDER_PORTS = [0]
RECEIVER_PORTS = [1]
INT_COLLECTOR_PORTS = [2]


class RealTrafficTrace(TRexTest, IntTest):
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
            dst_ipv4="0.0.0.0",
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=0,
            with_another_pkt_later=True,
            ig_port=self.port1,
            eg_port=self.port2,
            no_send=True,
        )

        # Put RX ports to promiscuous mode, otherwise it will drop all packets if the
        # destination mac is not the port mac address.
        # TODO: change based on port decision
        self.trex_client.set_port_attr(
            INT_COLLECTOR_PORTS + RECEIVER_PORTS, promiscuous=True
        )

        # Capture INT packets
        self.trex_client.set_service_mode(ports=INT_COLLECTOR_PORTS, enabled=True)
        capture = self.trex_client.start_capture(
            rx_ports=INT_COLLECTOR_PORTS,
            limit=CAPTURE_LIMIT,
            bpf_filter="udp and dst port 32766",
        )

        # Start sending stateless traffic
        self.trex_client.push_remote(
            REMOTE_PCAP_DIR + REMOTE_PCAP_FILE,
            speedup=mult,
            duration=TEST_DURATION,
            ports=SENDER_PORTS,
            src_mac_pcap=True,
            dst_mac_pcap=True
        )
        self.trex_client.wait_on_traffic(ports=SENDER_PORTS)

        output = "/tmp/real-traffic-trace-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.trex_client.stop_capture(capture["id"], output)
        analyze_report_pcap(output, TOTAL_FLOWS)
        list_port_status(self.trex_client.get_stats())

        # TODO: parse data and verify results

    def runTest(self):
        # TODO: iterate all possible parameters of test
        pkt = testutils.simple_udp_packet()
        self.doRunTest(TRAFFIC_MULT, pkt, [False, False], False, False, False)
