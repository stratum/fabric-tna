# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from trex_test import TRexTest
from base_test import *
from fabric_test import *
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont
from datetime import datetime
from xnt import analysis_report_pcap
# from trex_utils import list_port_status

TMP_MULT="10gbps"
TMP_DURATION=5

SENDER_PORTS = [0]
INT_COLLECTOR_PORTS = [3]

class IntMultipleFlows(TRexTest, IntTest):

    def doRunTest(self, pkt, is_device_spine, send_report_to_spine):

        # Install routing flows onto hardware switch
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)
        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=False,
            tagged2=False,
            is_next_hop_spine=False,
            prefix_len=32,
            with_another_pkt_later=True,
            ig_port=self.port0,
            eg_port=self.port1,
            no_send=True,
        )

        # Define stream
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())

        # Add stream to client
        self.trex_client.add_streams(stream, ports=SENDER_PORTS)

        # Set up capture
        pkt_capture_limit = TMP_DURATION * 3
        self.trex_client.set_service_mode(ports=INT_COLLECTOR_PORTS, enabled=True)
        capture = self.trex_client.start_capture(
            rx_ports=INT_COLLECTOR_PORTS,
            limit=pkt_capture_limit,
            bpf_filter="udp and dst port 32766",
        )

        # Start stateless traffic
        self.trex_client.start(ports=SENDER_PORTS, mult=TMP_MULT, duration=TMP_DURATION)
        self.trex_client.wait_on_traffic(ports=SENDER_PORTS)


        # Stop capturing traffic and save it
        output = "/tmp/int-single-flow-{}-{}.pcap".format(
            "dummy", datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.trex_client.stop_capture(capture["id"], output)
        analysis_report_pcap(output)
        # list_port_status(self.trex_client.get_stats())

        # TODO: parse data and verify results

    def runTest(self):
        # for test_args in get_test_args(traffic_dir="host-leaf-host", int_test_type="local"):
            # doRunTest(test_args)

        # TODO: pkt, is_device_spine, send_report_to_spine
        pkt = testutils.simple_tcp_packet()
        self.doRunTest(pkt, False, False)
