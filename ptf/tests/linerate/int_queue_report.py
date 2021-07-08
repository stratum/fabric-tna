# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from scapy.utils import PcapReader
from trex_test import TRexTest
from base_test import *
from fabric_test import *
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont, STLVM
from datetime import datetime

TRAFFIC_MULT="100%"
TEST_DURATION=10
DEFAULT_QID = 0
DEFAULT_QUOTA = 50
CAPTURE_LIMIT = 1024
THRESHOLD_TRIGGER = 101
THRESHOLD_RESET = 100

SENDER_PORTS = [0]
INT_COLLECTOR_PORTS = [2]
RECEIVER_PORTS = [3]

class IntQueueReportTest(TRexTest, IntTest):
    """
    This test will generate two streams, both streams will be sent to the same output port.
    Both streams will use 100% of bandwidth to send the traffic, and we expected
    this will cause some congestions to the output queue.
    Since there will be some congestions, we also expected to receive INT queue report
    from the switch.
    """

    @autocleanup
    def doRunTest(self, tagged, is_device_spine, send_report_to_spine, is_next_hop_spine):
        pkt = testutils.simple_udp_packet()
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine, watch_flow=False)
        self.set_up_latency_threshold_for_q_report(threshold_trigger=THRESHOLD_TRIGGER, threshold_reset=THRESHOLD_RESET)
        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            # Will send/receive traffic from TRex, this is for setting up flows for
            # ports and output ports.
            ig_port=self.port1,
            eg_port=self.port4,
            no_send=True,
        )
        self.set_queue_report_quota(self.port4, qid=DEFAULT_QID, quota=DEFAULT_QUOTA)

        # Define stream and stateless VM to change the IP source for each packet.
        vm = STLVM()
        vm.var(name="ip_id", min_value=0, max_value=0xFFFF, size=2, op="inc")
        vm.write(fv_name="ip_id", pkt_offset="IP.id")
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont())

        self.trex_client.add_streams(stream, ports=SENDER_PORTS)

        # Put RX ports to promiscuous mode, otherwise it will drop all packets if the
        # destination mac is not the port mac address.
        self.trex_client.set_port_attr(INT_COLLECTOR_PORTS + RECEIVER_PORTS, promiscuous=True)

        # Put port to service mode so we can capture packet from it.
        self.trex_client.set_service_mode(ports=INT_COLLECTOR_PORTS, enabled=True)
        capture = self.trex_client.start_capture(
            rx_ports=INT_COLLECTOR_PORTS,
            limit=CAPTURE_LIMIT,
            bpf_filter="udp and dst port 32766",
        )

        self.trex_client.start(ports=SENDER_PORTS, mult=TRAFFIC_MULT, duration=TEST_DURATION)
        self.trex_client.wait_on_traffic(ports=SENDER_PORTS)

        pcap_path = "/tmp/int-queue-report-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.trex_client.stop_capture(capture["id"], pcap_path)

        # Verify the following:
        # - Every packet must be an INT report
        # - Only queue reports, no flow report nor drop reports.
        # - Sequence number will be sequential per hw_id
        # - Latency in every queue report will higher than the threshold we set
        # - The total number of report will be less or equal to the report quota
        # - Egress port and queue must be the one we set
        # - The packets from the report is sequential (by checking the ID field from the IP header)
        pcap_reader =  PcapReader(pcap_path)
        report_pkt = None
        number_of_reports = 0
        hw_id_to_seq = {}
        ip_id = None
        while True:
            try:
                report_pkt = pcap_reader.recv()
            except (EOFError, KeyboardInterrupt):
                break
            except Exception:
                raise

            if INT_L45_REPORT_FIXED not in report_pkt:
                self.fail("Packet is not an INT report")
            if INT_L45_LOCAL_REPORT not in report_pkt:
                self.fail("Packet is not an INT local report")
            number_of_reports += 1

            int_fixed_header = report_pkt[INT_L45_REPORT_FIXED]
            int_local_report_header = report_pkt[INT_L45_LOCAL_REPORT]
            inner_ip_header = int_local_report_header[IP]
            hw_id = int_fixed_header.hw_id
            seq_no = int_fixed_header.seq_no
            ingress_time = int_fixed_header.ingress_tstamp
            egress_time = int_local_report_header.egress_tstamp
            latency = egress_time - ingress_time
            egress_port = int_local_report_header.egress_port_id
            egress_queue = int_local_report_header.queue_id

            self.failIf(int_fixed_header.d != 0, "Received an unexpected drop report")
            self.failIf(int_fixed_header.f != 0, "Received an unexpected flow report")
            self.failIf(int_fixed_header.q != 1, "Not a queue report")
            self.failIf(egress_port != self.port4, f"Unexpected egress port {egress_port}")
            self.failIf(egress_queue != DEFAULT_QID, f"Unexpected queue id {egress_queue}")

            if hw_id not in hw_id_to_seq:
                hw_id_to_seq[hw_id] = seq_no
            else:
                self.failIf(
                    hw_id_to_seq[hw_id] != (seq_no - 1),
                    f"Sequential number is wrong, should be {hw_id_to_seq[hw_id]+1}, but got {seq_no}."
                )
                hw_id_to_seq[hw_id] = seq_no

            # 32-bit timestamp overflow case
            if latency < 0:
                latency += 0xffffffff

            self.failIf(
                latency < THRESHOLD_TRIGGER,
                f"Latency should be higher than trigger {THRESHOLD_TRIGGER}, got {latency}"
            )

            new_id = inner_ip_header.id
            if ip_id is not None:
                self.failIf(new_id != ip_id + 1, f"Expect to get IP ID {ip_id + 1}, but got {new_id}")
            ip_id = new_id

        self.failIf(
            number_of_reports > DEFAULT_QUOTA,
            f"The number of report is more than the quota, expecte {DEFAULT_QUOTA}, got {number_of_reports}"
        )

        print(f"Total number of INT reports received: {number_of_reports}")


    def runTest(self):
        self.doRunTest([False, False], False, False, False)