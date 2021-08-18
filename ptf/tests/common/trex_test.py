# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from base_test import *
from trex.stl.api import STLClient

from bmd_bytes import BMD_BYTES
from fabric_test import StatsTest, STATS_INGRESS, STATS_EGRESS
from trex_utils import FlowStats


class TRexTest(P4RuntimeTest, StatsTest):
    trex_client: STLClient

    def setUp(self):
        super(TRexTest, self).setUp()
        trex_server_addr = ptf.testutils.test_param_get("trex_server_addr")
        self.trex_client = STLClient(server=trex_server_addr)
        self.trex_client.connect()
        self.trex_client.acquire()
        self.trex_client.reset()  # Resets configs from all ports
        self.trex_client.clear_stats()  # Clear status from all ports
        # Put all ports to promiscuous mode, otherwise they will drop all
        # incoming packets if the destination mac is not the port mac address.
        self.trex_client.set_port_attr(
            self.trex_client.get_all_ports(), promiscuous=True
        )

    def tearDown(self):
        print("Tearing down STLClient...")
        self.trex_client.stop()
        self.trex_client.release()
        self.trex_client.disconnect()
        super(TRexTest, self).tearDown()

    def get_switch_flow_stats(self, stats_flow_id, ig_port, eg_port, **ftuple) -> FlowStats:
        ig_bytes, ig_packets = self.get_stats_counter(
            gress=STATS_INGRESS, stats_flow_id=stats_flow_id, port=ig_port, **ftuple)
        eg_bytes, eg_packets = self.get_stats_counter(
            gress=STATS_EGRESS, stats_flow_id=stats_flow_id, port=eg_port, **ftuple)
        # Switch egress bytes count will include bridged metadata, we need to subtract
        # that to obtain the actual bytes transmitted by the switch.
        tx_bytes = eg_bytes - eg_packets * BMD_BYTES
        return FlowStats(
            pg_id=stats_flow_id,
            tx_packets=eg_packets,
            rx_packets=ig_packets,
            tx_bytes=tx_bytes,
            rx_bytes=ig_bytes,
        )
