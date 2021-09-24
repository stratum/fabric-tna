# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

import os
from collections import deque

from base_test import *
from fabric_test import *
from ptf.testutils import group
from scapy.utils import PcapReader
from trex_stl_lib.api import STLVM, STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest

TRAFFIC_MULT = "1"
RATE = 1000  # pps
TEST_DURATION = 3
DEFAULT_QID = 1
SLICE_ID = 1
TC = 1
DEFAULT_QUOTA = 50
INT_REPORT_CAPTURE_LIMIT = 100
RX_LIMIT = 4000  # max number of packets captured from the switch.
THRESHOLD_TRIGGER = 100  # ns
THRESHOLD_RESET = 1  # ns

SENDER_PORT = 0
INT_COLLECTOR_PORT = 2
RECEIVER_PORT = 3


@group("int")
class IntQueueReportTest(TRexTest, IntTest, SlicingTest):
    @autocleanup
    def doRunTest(
        self, tagged1, tagged2, is_device_spine, send_report_to_spine, is_next_hop_spine
    ):
        print(
            f"Testing tagged1={tagged1}, tagged2={tagged2}, is_device_spine={is_device_spine}, send_report_to_spine={send_report_to_spine}, is_next_hop_spine={is_next_hop_spine}"
        )
        # TODO: move these to auto cleanup annonation?
        self.trex_client.reset()
        self.trex_client.clear_stats()

        pkt = testutils.simple_udp_packet()
        if tagged1:
            pkt = pkt_add_vlan(pkt, vlan_vid=VLAN_ID_1)
        self.set_up_int_flows(
            is_device_spine, pkt, send_report_to_spine, watch_flow=False
        )
        self.set_up_latency_threshold_for_q_report(
            threshold_trigger=THRESHOLD_TRIGGER,
            threshold_reset=THRESHOLD_RESET,
            queue_id=DEFAULT_QID,
        )
        if is_next_hop_spine:
            # If MPLS test, port2 is assumed to be a spine port, with
            # default vlan untagged.
            vlan2 = DEFAULT_VLAN
            assert not tagged2
        else:
            vlan2 = VLAN_ID_2
        self.set_up_ipv4_unicast_rules(
            next_hop_mac=HOST2_MAC,
            ig_port=self.port1,
            eg_port=self.port4,
            dst_ipv4=pkt[IP].dst,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            switch_mac=pkt[Ether].dst,
            vlan2=vlan2,
        )
        self.set_queue_report_quota(self.port4, qid=DEFAULT_QID, quota=DEFAULT_QUOTA)

        # To avoid reporting INT report packet, we use queue ID 1 for the traffic.
        self.add_slice_tc_classifier_entry(
            slice_id=SLICE_ID, tc=TC, ipv4_dst=pkt[IP].dst,
        )
        self.add_queue_entry(slice_id=SLICE_ID, tc=TC, qid=DEFAULT_QID)

        # Define stream and stateless VM to change the IP source for each packet.
        vm = STLVM()
        vm.var(
            name="ip_src",
            min_value="10.0.0.1",
            max_value="10.255.255.255",
            size=4,
            op="inc",
            step=1,
        )
        vm.write(fv_name="ip_src", pkt_offset="IP.src")
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont(pps = RATE))
        self.trex_client.add_streams(stream, ports=[SENDER_PORT])

        # Put RX ports to promiscuous mode, otherwise it will drop all packets if the
        # destination mac is not the port mac address.
        self.trex_client.set_port_attr(
            [INT_COLLECTOR_PORT, RECEIVER_PORT], promiscuous=True
        )

        # Put port to service mode so we can capture packet from it.
        self.trex_client.set_service_mode(
            ports=[INT_COLLECTOR_PORT, RECEIVER_PORT], enabled=True
        )
        int_capture = self.trex_client.start_capture(
            rx_ports=[INT_COLLECTOR_PORT], limit=INT_REPORT_CAPTURE_LIMIT
        )
        rx_capture = self.trex_client.start_capture(
            rx_ports=[RECEIVER_PORT], limit=RX_LIMIT
        )

        self.trex_client.start(
            ports=[SENDER_PORT], mult=TRAFFIC_MULT, duration=TEST_DURATION
        )
        self.trex_client.wait_on_traffic(ports=[SENDER_PORT])

        pcap_dir = f"/tmp/{self.__class__.__name__}"
        if not os.path.exists(pcap_dir):
            os.makedirs(pcap_dir)
        pcap_path = f"{pcap_dir}/int-reports.pcap"
        rx_pcap_path = f"{pcap_dir}/traffic.pcap"
        self.trex_client.stop_capture(int_capture["id"], pcap_path)
        self.trex_client.stop_capture(rx_capture["id"], rx_pcap_path)

        # Check if we receive every packets we sent.
        port_stats = self.trex_client.get_stats()
        sent_packets = port_stats[SENDER_PORT]["opackets"]
        recv_packets = port_stats[RECEIVER_PORT]["ipackets"]
        self.failIf(sent_packets != recv_packets, "Didn't receive all packets")

        # Verify the following:
        # - Every packet must be an INT report
        # - Only queue reports, no flow report nor drop reports.
        # - Sequence number will be sequential per hw_id
        # - Latency in every queue report will higher than the threshold we set
        # - The total number of report will be less or equal to the report quota
        # - Egress port and queue must be the one we set
        pcap_reader = PcapReader(pcap_path)
        report_pkt = None
        number_of_reports = 0
        hw_id_to_seq = {}
        reported_ip_srcs = deque()
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

            self.failIf(int_fixed_header.d != 0, "Received an unexpected drop report")
            self.failIf(int_fixed_header.f != 0, "Received an unexpected flow report")
            self.failIf(int_fixed_header.q != 1, "Not a queue report")
            self.failIf(
                INT_L45_LOCAL_REPORT in inner_ip_header,
                "Unexpected report-in-report packet.",
            )

            number_of_reports += 1
            hw_id = int_fixed_header.hw_id
            seq_no = int_fixed_header.seq_no
            ingress_time = int_fixed_header.ingress_tstamp
            egress_time = int_local_report_header.egress_tstamp
            latency = egress_time - ingress_time
            egress_port = int_local_report_header.egress_port_id
            egress_queue = int_local_report_header.queue_id

            self.failIf(
                egress_port != self.port4, f"Unexpected egress port {egress_port}"
            )
            self.failIf(
                egress_queue != DEFAULT_QID, f"Unexpected queue id {egress_queue}"
            )

            if hw_id not in hw_id_to_seq:
                hw_id_to_seq[hw_id] = seq_no
            else:
                self.failIf(
                    hw_id_to_seq[hw_id] != (seq_no - 1),
                    f"Sequence number is wrong, should be {hw_id_to_seq[hw_id]+1}, but got {seq_no}.",
                )
                hw_id_to_seq[hw_id] = seq_no

            # 32-bit timestamp overflow case
            if latency < 0:
                latency += 0xFFFFFFFF

            self.failIf(
                latency < THRESHOLD_TRIGGER,
                f"Latency should be higher than trigger {THRESHOLD_TRIGGER}, got {latency}",
            )
            reported_ip_srcs.append(inner_ip_header.src)

        pcap_reader.close()

        self.failIf(
            number_of_reports != DEFAULT_QUOTA,
            f"The number of reports is more than the quota, expected {DEFAULT_QUOTA}, got {number_of_reports}",
        )
        self.failIf(number_of_reports == 0, "No INT reports received")

        # In this section we will verify if the switch is reporting all congested packets.
        # We will try to find a subset of packets from the RX capture.
        # The reason we need to compare from the RX capture is because we can't guarantee
        # that the packet from TRex is in order, so we cannot just check if IP addresses
        # are sequential.
        pcap_reader = PcapReader(rx_pcap_path)
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
                if ip_src != reported_ip_srcs[0]:
                    self.fail(f"Expected IP src {ip_src}, got {reported_ip_srcs[0]}")
                else:
                    reported_ip_srcs.popleft()
            else:
                if ip_src == reported_ip_srcs[0]:
                    checking_ip_src = True
                    reported_ip_srcs.popleft()
            if len(reported_ip_srcs) == 0:
                break
        pcap_reader.close()
        self.failIf(
            len(reported_ip_srcs) != 0,
            f"Received {len(reported_ip_srcs)} unexpected report(s)",
        )

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
                        for send_report_to_spine in [False, True]:
                            self.doRunTest(
                                tagged1,
                                tagged2,
                                is_device_spine,
                                send_report_to_spine,
                                is_next_hop_spine,
                            )
