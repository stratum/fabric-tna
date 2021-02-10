# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
from argparse import ArgumentParser
from datetime import datetime

from lib.base_test import StatelessTest
from lib.gtpu import GTPU
from lib.utils import list_port_status
from lib.xnt import analysis_report_pcap
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:03"
SOURCE_IP = "192.168.10.1"
DEST_IP = "192.168.30.1"
INNER_SRC_IP = "10.240.0.1"
INNER_DEST_IP = "8.8.8.8"
SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]


class IntSingleFlow(StatelessTest):
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument("--duration", type=int, help="Test duration", default=5)
        parser.add_argument(
            "--mult", type=str, help="Traffic multiplier", default="1pps"
        )
        parser.add_argument("--pkt-type", type=str, help="Packet type", default="tcp")

    def get_sample_packet(self, pkt_type):
        if pkt_type == "tcp":
            return Ether() / IP(src=SOURCE_IP, dst=DEST_IP) / TCP() / ("*" * 1500)
        elif pkt_type == "gtpu-udp":
            return (
                    Ether()
                    / IP(src=SOURCE_IP, dst=DEST_IP)
                    / UDP()
                    / GTPU()
                    / IP()
                    / UDP()
                    / ("*" * 1500)
            )
        else:
            return Ether() / IP(src=SOURCE_IP, dst=DEST_IP) / UDP() / ("*" * 1500)

    def start(self, args) -> None:
        pkt = self.get_sample_packet(args.pkt_type)
        if not pkt:
            return 1

        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())

        logging.info("Setting up ports")
        self.client.add_streams(stream, ports=SENDER_PORTS)

        pkt_capture_limit = args.duration * 3
        logging.info(
            "Start capturing first %s RX packet from INT collector", pkt_capture_limit
        )
        self.client.set_service_mode(ports=INT_COLLECTPR_PORTS, enabled=True)
        capture = self.client.start_capture(
            rx_ports=INT_COLLECTPR_PORTS,
            limit=pkt_capture_limit,
            bpf_filter="udp and dst port 32766",
        )

        logging.info(
            "Starting traffic, duration: %ds, throughput: %s", args.duration, args.mult
        )
        self.client.start(ports=SENDER_PORTS, mult=args.mult, duration=args.duration)
        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")
        output = "/tmp/int-single-flow-{}-{}.pcap".format(
            args.pkt_type, datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.client.stop_capture(capture["id"], output)
        analysis_report_pcap(output)
        list_port_status(self.client.get_stats())
