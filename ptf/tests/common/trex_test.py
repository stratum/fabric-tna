# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from base_test import *
from trex.stl.api import STLClient
from subprocess import Popen
import pickle


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
        code = "import pickle\n" \
               "from xnt import analyze_report_pcap\n"

        if total_flows:
            code += f"result = analyze_report_pcap('{pcap_file}', {total_flows})\n"
        else:
            code += f"result = analyze_report_pcap('{pcap_file}')\n"

        code += "with open('trace.pickle', 'wb') as handle:\n" \
                "    pickle.dump(result, handle, protocol=pickle.HIGHEST_PROTOCOL)"

        cmd = ["pypy", "-c", code]

        try:
            p = Popen(cmd)
            p.wait()

            with open('trace.pickle', 'rb') as handle:
                result = pickle.load(handle)

            return result

        except Exception as e:
            print("Error when parsing pcap: {}".format(e))
