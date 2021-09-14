# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
from concurrent.futures import ThreadPoolExecutor

from base_test import *
from trex.stl.api import STLClient


class TRexTest(P4RuntimeTest):
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
        self.thread_pool = ThreadPoolExecutor(10)

    def tearDown(self):
        print("Tearing down STLClient...")
        self.trex_client.stop()
        self.trex_client.release()
        self.trex_client.disconnect()
        self.thread_pool.shutdown(wait=False)
        super(TRexTest, self).tearDown()
