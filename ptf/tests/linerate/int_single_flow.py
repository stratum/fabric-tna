from trex_test import *
from base_test import autocleanup, tvsetup, tvskip
from fabric_test import *
from ptf.testutils import group
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.sctp import SCTP
from scapy.layers.vxlan import VXLAN
from scapy.packet import bind_layer
import logging
import sys

TMP_MULT="1pps"
TMP_DURATION=5

@group("int")
class IntSingleFlow(TRexTest, IntTest):

    def doRunTest(self, pkt, is_device_spine, send_report_to_spine):

        # Install routing flows onto hardware switch
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)
        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            with_another_pkt_later=True,
            ig_port=ig_port,
            eg_port=eg_port,
            no_send=True,
        )

        # Connect TRex stateless client
        success = self.trex_client.setUp()
        if not success:
            sys.exit(1)

        # Define generic TCP/IP packet, 1500 byte payload
        p = Ether() / IP(src=SOURCE_IP, dst=DEST_IP) / TCP() / ("*" * 1500)

        # Define stream
        stream = STLStream(packet=STLPktBuilder(pkt=p, vm=[]), mode=STLTXCont())

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

        # Close client once it has finished running
        success = self.tearDown()
        if not success:
            sys.exit(2)

        # Stop capturing traffic and save it
        output = "/tmp/int-single-flow-{}-{}.pcap".format(
            args.pkt_type, datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.trex_client.stop_capture(capture["id"], output)
        analysis_report_pcap(output)
        list_port_status(self.trex_client.get_stats()

        # TODO: parse data and verify results

    def runTest(self):
        # for test_args in get_test_args(traffic_dir="host-leaf-host", int_test_type="local"):
            # doRunTest(test_args)

        # TODO: pkt, is_device_spine, send_report_to_spine
        doRunTest(...)
