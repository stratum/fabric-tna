# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from scapy.utils import PcapReader
from trex_test import TRexTest
from base_test import *
from fabric_test import *
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont, STLVM
from collections import deque

TRAFFIC_MULT="1100pps"
TEST_DURATION=3
DEFAULT_QID = 0
DEFAULT_QUOTA = 50
INT_REPORT_CAPTURE_LIMIT = 100
RX_LIMIT = 4000 # limit for capturing the traffic from the switch.
THRESHOLD_TRIGGER = 1000
THRESHOLD_RESET = 1

SENDER_PORT = [0]
INT_COLLECTOR_PORT = [2]
RECEIVER_PORT = [3]

class IntQueueReportTest(TRexTest, IntTest):
    """
    This test will generate one stream with multiple packets with a sequence of source IP
    addresses. (10.0.0.0~10.255.255.255)
    On the Stratum side we need to configure port shaper to limit the rate of packets to
    1000pps. In the test we will use a higher rate to send packets to the switch.
    We expect to see some congestions and receive INT queue report from the switch.
    """

    @autocleanup
    def doRunTest(self, tagged1, tagged2, is_device_spine, send_report_to_spine, is_next_hop_spine):
        print(f"Testing tagged1={tagged1}, tagged2={tagged2}, is_device_spine={is_device_spine}, send_report_to_spine={send_report_to_spine}, is_next_hop_spine={is_next_hop_spine}")
        pkt = testutils.simple_udp_packet()
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine, watch_flow=False)
        self.set_up_latency_threshold_for_q_report(threshold_trigger=THRESHOLD_TRIGGER, threshold_reset=THRESHOLD_RESET)
        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged1,
            tagged2=tagged2,
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
        vm.var(name="ip_src", min_value="10.0.0.1", max_value="10.255.255.255", size=4, op="inc", step=1)
        vm.write(fv_name="ip_src", pkt_offset="IP.src")
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont())
        self.trex_client.add_streams(stream, ports=SENDER_PORT)

        # Put RX ports to promiscuous mode, otherwise it will drop all packets if the
        # destination mac is not the port mac address.
        self.trex_client.clear_stats()
        self.trex_client.set_port_attr(INT_COLLECTOR_PORT + RECEIVER_PORT, promiscuous=True)

        # Put port to service mode so we can capture packet from it.
        self.trex_client.set_service_mode(ports=INT_COLLECTOR_PORT + RECEIVER_PORT, enabled=True)
        int_capture = self.trex_client.start_capture(
            rx_ports=INT_COLLECTOR_PORT,
            limit=INT_REPORT_CAPTURE_LIMIT,
            bpf_filter="udp and dst port 32766",
        )
        rx_capture = self.trex_client.start_capture(
            rx_ports=RECEIVER_PORT,
            limit=RX_LIMIT,
            bpf_filter="ip src net 10.0.0.0/8",
        )

        self.trex_client.start(ports=SENDER_PORT, mult=TRAFFIC_MULT, duration=TEST_DURATION)
        self.trex_client.wait_on_traffic(ports=SENDER_PORT)

        pcap_path = "/tmp/int-queue-report.pcap"
        rx_pcap_path = "/tmp/int-queue-report-rx.pcap"
        self.trex_client.stop_capture(int_capture["id"], pcap_path)
        self.trex_client.stop_capture(rx_capture["id"], rx_pcap_path)

        # Verify the following:
        # - Every packet must be an INT report
        # - Only queue reports, no flow report nor drop reports.
        # - Sequence number will be sequential per hw_id
        # - Latency in every queue report will higher than the threshold we set
        # - The total number of report will be less or equal to the report quota
        # - Egress port and queue must be the one we set
        # - The packets from the report is sequential by checking the source IP
        pcap_reader =  PcapReader(pcap_path)
        report_pkt = None
        number_of_reports = 0
        hw_id_to_seq = {}
        ips = deque()
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

            int_fixed_header = report_pkt[INT_L45_REPORT_FIXED]
            int_local_report_header = report_pkt[INT_L45_LOCAL_REPORT]
            inner_ip_header = int_local_report_header[IP]

            if INT_L45_LOCAL_REPORT in inner_ip_header:
                continue

            number_of_reports += 1
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
            ips.append(inner_ip_header.src)


        pcap_reader.close()

        self.failIf(
            number_of_reports > DEFAULT_QUOTA,
            f"The number of report is more than the quota, expecte {DEFAULT_QUOTA}, got {number_of_reports}"
        )

        print(f"Total number of INT reports received: {number_of_reports}")
        self.failIf(number_of_reports == 0, "No INT reports received")

        # This section we will verify if the switch is reporting all congested packets.
        # We will try to find a subset of packets from the RX capture.
        # The reason we need to compare from the RX capture is because we can't guarantee
        # that the packet from TRex is in order, so we cannot just check if IP addresses
        # are sequential.
        pcap_reader =  PcapReader(rx_pcap_path)
        checking_ip_src = False
        while True:
            try:
                pkt = pcap_reader.recv()
            except (EOFError, KeyboardInterrupt):
                break
            except Exception:
                raise
            if IP not in pkt:
                continue
            ip_src = pkt[IP].src
            if checking_ip_src:
                if ip_src != ips[0]:
                    self.fail(f"Expect IP src {ip_src}, got {ips[0]}")
                else:
                    ips.popleft()
            else:
                if ip_src == ips[0]:
                    checking_ip_src = True
                    ips.popleft()
            if len(ips) == 0:
                break

        self.failIf(len(ips) != 0, f"Receive {len(ips)} unexpected report(s)")
        pcap_reader.close()


    def runTest(self):
        print("")
        for is_device_spine in [False, True]:
            for tagged1 in [False, True]:
                for tagged2 in [False, True]:
                    if is_device_spine and (tagged1 or tagged2):
                        continue
                    for is_next_hop_spine in [False, True]:
                        if is_next_hop_spine and tagged2:
                            continue
                        self.doRunTest(tagged1, tagged2, is_device_spine, False, is_next_hop_spine)
