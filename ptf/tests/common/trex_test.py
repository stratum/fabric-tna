# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from base_test import *
from trex.stl.api import STLClient
from subprocess import Popen, PIPE


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

    def tearDown(self):
        print("Tearing down STLClient...")
        self.trex_client.stop()
        self.trex_client.release()
        self.trex_client.disconnect()
        super(TRexTest, self).tearDown()

    def pypy_parse_pcap(self, pcap_file: str, total_flows: str = None) -> dict:
        cmd = ["pypy", "test.py", pcap_file]
        if total_flows:
            cmd.append(total_flows)

        try:
            p = Popen(cmd, stdout=PIPE)
            output, _ = p.communicate()
            out = output.decode('UTF-8')
            print(out)

            results = out.splitlines()

            scores = {}
            for result in results:
                if "Drop report filter accuracy" in result:
                    scores["drop_accuracy_score"] = float(result.split(" ")[-1])
                elif "Drop report filter efficiency" in result:
                    scores["drop_efficiency_score"] = float(result.split(" ")[-1])
                elif "Flow report filter accuracy" in result:
                    scores["flow_accuracy_score"] = float(result.split(" ")[-1])
                elif "Flow report filter efficiency" in result:
                    scores["flow_efficiency_score"] = float(result.split(" ")[-1])

            return scores

        except Exception as e:
            print("Error when parsing pcap: {}".format(e))
