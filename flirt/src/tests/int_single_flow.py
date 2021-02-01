# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
from argparse import ArgumentParser
from datetime import datetime

from flirt_lib.base import StatelessTest
from flirt_lib.gtpu import GTPU
from flirt_lib.utils import list_port_status
from flirt_lib.xnt import analysis_report_pcap
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont
from fabric_test import *
log = logging.getLogger("INT Single Flow")
log.setLevel(logging.INFO)

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:03"
COL_MAC = "00:00:00:00:00:04"
COL_IP = "192.168.40.1"
SWITCH_MAC = "c0:ff:ee:c0:ff:ee"
SOURCE_IP = "192.168.10.1"
DEST_IP = "192.168.30.1"
SWITCH_IP = "192.168.40.254"
INNER_SRC_IP = "10.240.0.1"
INNER_DEST_IP = "8.8.8.8"
IP_PREFIX = 32
SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]
SWITCH_PORTS = [272, 280, 256, 264]  # 29, 30, 31, 32
DEFAULT_VLAN = 10
SWITCH_ID = 1
INT_REPORT_MIRROR_IDS = [300, 301, 302, 303]
RECIRC_PORTS = [68, 196, 324, 452]


class IntSingleFlow(StatelessTest, FabricTest):
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        StatelessTest.setup_subparser(parser)
        parser.add_argument("--duration", type=int, help="Test duration", default=5)
        parser.add_argument(
            "--mult", type=str, help="Traffic multiplier", default="1pps"
        )
        parser.add_argument("--pkt-type", type=str, help="Packet type", default="tcp")

    def get_sample_packet(self, pkt_type):
        if pkt_type == "tcp":
            return (
                Ether(src=SOURCE_MAC, dst=SWITCH_MAC)
                / IP(src=SOURCE_IP, dst=DEST_IP)
                / TCP()
                / ("*" * 1500)
            )
        elif pkt_type == "gtpu-udp":
            return (
                Ether(src=SOURCE_MAC, dst=SWITCH_MAC)
                / IP(src=SOURCE_IP, dst=DEST_IP)
                / UDP()
                / GTPU()
                / IP()
                / UDP()
                / ("*" * 1500)
            )
        else:
            # UDP
            return (
                Ether(src=SOURCE_MAC, dst=SWITCH_MAC)
                / IP(src=SOURCE_IP, dst=DEST_IP)
                / UDP()
                / ("*" * 1500)
            )

    def set_up_p4_entries(self, args) -> None:
        # Filtering rules
        for i in range(0, 4):
            self.setup_port(SWITCH_PORTS[i], DEFAULT_VLAN)
            self.set_forwarding_type(
                SWITCH_PORTS[i],
                SWITCH_MAC,
                ethertype=ETH_TYPE_IPV4,
                fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )
        # Forwarding rules
        self.add_forwarding_routing_v4_entry(DEST_IP, IP_PREFIX, 100)
        self.add_forwarding_routing_v4_entry(COL_IP, IP_PREFIX, 101)

        # Next rules
        # Send to the dest host
        self.add_next_routing(100, SWITCH_PORTS[1], SWITCH_MAC, DEST_MAC)
        # Send to the collector
        self.add_next_routing(101, SWITCH_PORTS[3], SWITCH_MAC, COL_MAC)
        self.add_next_vlan(100, DEFAULT_VLAN)
        self.add_next_vlan(101, DEFAULT_VLAN)
        # INT rules
        self.set_up_watchlist_flow(SOURCE_IP, DEST_IP)
        self.set_up_int_mirror_flow(SWITCH_ID)
        self.set_up_report_flow(SWITCH_MAC, COL_MAC, SWITCH_IP, COL_IP, SWITCH_PORTS[3])

        for i in range(0, 4):
            self.set_up_report_mirror_flow(INT_REPORT_MIRROR_IDS[i], RECIRC_PORTS[i])

    def start(self, args) -> None:
        pkt = self.get_sample_packet(args.pkt_type)
        if not pkt:
            return 1

        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())

        log.info("Setting up ports")
        self.client.add_streams(stream, ports=SENDER_PORTS)

        pkt_capture_limit = args.duration * 3
        log.info(
            "Start capturing first %s RX packet from INT collector", pkt_capture_limit
        )
        self.client.set_service_mode(ports=INT_COLLECTPR_PORTS, enabled=True)
        capture = self.client.start_capture(
            rx_ports=INT_COLLECTPR_PORTS,
            limit=pkt_capture_limit,
            bpf_filter="udp and dst port 32766",
        )

        log.info(
            "Starting traffic, duration: %ds, throughput: %s", args.duration, args.mult
        )
        self.client.start(ports=SENDER_PORTS, mult=args.mult, duration=args.duration)
        log.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORTS)

        log.info("Stop capturing packet from INT collector port")
        output = "/tmp/int-single-flow-{}-{}.pcap".format(
            args.pkt_type, datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.client.stop_capture(capture["id"], output)
        analysis_report_pcap(output)
        list_port_status(self.client.get_stats())
