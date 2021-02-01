# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from argparse import ArgumentParser
from datetime import datetime

from flirt_lib.base import StatelessTest
from flirt_lib.utils import list_port_status
from flirt_lib.xnt import analysis_report_pcap
from fabric_test import *

UPSTREAM_ROUTER_MAC = "00:00:00:00:00:03"
COLLECTOR_MAC = "00:00:00:00:00:04"
COLLECTOR_IP = "192.168.40.1"
SWITCH_MAC = "c0:ff:ee:c0:ff:ee"
SOURCE_IP = "192.168.10.1"
SWITCH_IP = "192.168.40.254"

SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]
SWITCH_PORTS = [272, 280, 256, 264]  # 29, 30, 31, 32
DEFAULT_VLAN = 10
SWITCH_ID = 1
INT_REPORT_MIRROR_IDS = [300, 301, 302, 303]
RECIRC_PORTS = [68, 196, 324, 452]


class RemotePcap(StatelessTest, FabricTest):

    # setup_subparser is an optional class method
    # You can implement this method if you want to add additional command line
    # parameters for your test.
    # Those parameters will be parsed and be passed to the "start" method below as
    # "args" argument.
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--remote-pcap-file-dir",
            type=str,
            help="The directory which stores pcap files on the remove server.",
            default="/",
        )
        parser.add_argument(
            "--remote-pcap-files",
            type=str,
            help="The PCAP files which stores in remote server",
            required=True,
            nargs="+",
        )
        parser.add_argument(
            "--speed-multiplier", type=float, help="The speed multiplier", default=1
        )
        parser.add_argument("--duration", type=float, help="Test duration", default=-1)
        parser.add_argument(
            "--capture-limit", type=int, default=1000, help="INT report capture limit"
        )
        parser.add_argument(
            "--total-flows",
            type=int,
            default=0,
            help="Total flows(5-tuple) in the traffic trace, this number is used to"
            + "analysis the accuracy score",
        )

    def set_up_p4_entries(self, args) -> None:
        # Filtering rules
        for i in range(0, 4):
            self.set_up_port(SWITCH_PORTS[i], DEFAULT_VLAN)
            self.set_forwarding_type(
                SWITCH_PORTS[i],
                SWITCH_MAC,
                ethertype=ETH_TYPE_IPV4,
                fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )
        # Forwarding rules
        self.add_forwarding_routing_v4_entry("0.0.0.0", 1, 100)
        self.add_forwarding_routing_v4_entry("128.0.0.0", 1, 100)
        self.add_forwarding_routing_v4_entry(COLLECTOR_IP, 32, 101)

        # Next rules
        # Send to the upstream router
        self.add_next_routing(100, SWITCH_PORTS[2], SWITCH_MAC, UPSTREAM_ROUTER_MAC)
        # Send to the collector
        self.add_next_routing(101, SWITCH_PORTS[3], SWITCH_MAC, COLLECTOR_MAC)
        self.add_next_vlan(100, DEFAULT_VLAN)
        self.add_next_vlan(101, DEFAULT_VLAN)
        # INT rules
        self.set_up_watchlist_flow(
            ipv4_src="0.0.0.0",
            ipv4_src_mask="128.0.0.0",
            ipv4_dst="0.0.0.0",
            ipv4_dst_mask="128.0.0.0",
        )
        self.set_up_watchlist_flow(
            ipv4_src="128.0.0.0",
            ipv4_src_mask="128.0.0.0",
            ipv4_dst="128.0.0.0",
            ipv4_dst_mask="128.0.0.0",
        )
        self.set_up_int_mirror_flow(SWITCH_ID)
        self.set_up_report_flow(
            SWITCH_MAC, COLLECTOR_MAC, SWITCH_IP, COLLECTOR_IP, SWITCH_PORTS[3]
        )

        for i in range(0, 4):
            self.set_up_report_mirror_flow(INT_REPORT_MIRROR_IDS[i], RECIRC_PORTS[i])

    # The entrypoint of a test
    def start(self, args: dict) -> None:
        logging.info(
            "Start capturing first %s RX packet from INT collector", args.capture_limit
        )

        # Start capturing packet from INT collector port
        self.client.set_service_mode(ports=INT_COLLECTPR_PORTS, enabled=True)
        capture = self.client.start_capture(
            rx_ports=INT_COLLECTPR_PORTS,
            limit=args.capture_limit,
            bpf_filter="udp and dst port 32766",
        )

        logging.info(
            "Starting traffic, speedup: %f", args.speed_multiplier,
        )
        duration = args.duration
        if args.duration > 0:
            duration = args.duration / len(args.remote_pcap_files)
        for remote_pcap_file in args.remote_pcap_files:
            # Start the traffic on ports with given duration, speedup, and pcap file.
            self.client.push_remote(
                args.remote_pcap_file_dir + os.path.sep + remote_pcap_file,
                speedup=args.speed_multiplier,
                duration=duration,
                ports=SENDER_PORTS,
            )

            logging.info("Sending packets from file {}....".format(remote_pcap_file))
            self.client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")
        list_port_status(self.client.get_stats())

        output = "/tmp/remote-pcap-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )

        self.client.stop_capture(capture["id"], output)
        logging.info("INT report pcap file stored in {}".format(output))
        logging.info("Analyzing report pcap file...")
        analysis_report_pcap(output, args.total_flows)
