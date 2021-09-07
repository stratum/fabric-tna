# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime
from pprint import pprint

from trex.astf.api import *
from base_test import *
from fabric_test import *
from ptf.testutils import group
from trex_test import TRexAstfTest
from trex_utils import list_port_status
from xnt import analyze_report_pcap

# Test specs
TRAFFIC_MULT = 1000.0
TEST_DURATION = 10
CAPTURE_LIMIT = 20

# TCP tunables
SIZE = 1
LOOP = 10
WIN = 32
MSS = 0

RECEIVER_PORT = [1]

class AstfTcpFlow(TRexAstfTest):
    """
    TODO: pydoc
    """

    def _setup_basic_forwarding(self, out_port) -> None:
        in_ports = [self.port1, self.port2, self.port3, self.port4]
        for port in set(in_ports + [out_port]):
            self.setup_port(port, DEFAULT_VLAN, PORT_TYPE_EDGE)
        for in_port in in_ports:
            self.add_forwarding_acl_set_output_port(out_port, ig_port=in_port)

    def setup_basic_forwarding_to_1g(self) -> None:
        # Forwards all traffic to 1G shaped port per chassis config
        self._setup_basic_forwarding(out_port=self.port2)

    def setup_basic_forwarding_to_40g(self) -> None:
        # Forwards all traffic to 40G port per chassis config
        self._setup_basic_forwarding(out_port=self.port1)

    @autocleanup
    def runTest(self):

        self.trex_client.reset()
        self.trex_client.clear_stats()

        self.setup_basic_forwarding_to_1g()

        capture = self.trex_client.start_capture(
            rx_ports=RECEIVER_PORT, limit=CAPTURE_LIMIT
        )

        passed = True

        try:
            # load ASTF profile
            profile_path = '/fabric-tna/ptf/tests/linerate/http_eflow2.py'

            profile_tunables = {'size': SIZE, 'loop': LOOP, 'mss': MSS}
            self.trex_client.load_profile(profile = profile_path, tunables = profile_tunables)

            print("Injecting with multiplier of '%s' for %s seconds" % (TRAFFIC_MULT, TEST_DURATION))
            self.trex_client.start(mult = TRAFFIC_MULT, duration = TEST_DURATION, client_mask=1)

            self.trex_client.wait_on_traffic()

            output = "/tmp/tcp-recv-port-{}.pcap".format(
                datetime.now().strftime("%Y%m%d-%H%M%S")
            )
            self.trex_client.stop_capture(capture["id"], output)
            stats = self.trex_client.get_stats()

            # use this for debug info on all the stats
            pprint(stats)

            if self.trex_client.get_warnings():
                print('\n\n*** test had warnings ****\n\n')
                for w in self.trex_client.get_warnings():
                    print(w)


            client_stats = stats['traffic']['client']
            server_stats = stats['traffic']['server']

            tcp_client_sent, tcp_server_recv = client_stats.get('tcps_sndbyte', 0), server_stats.get('tcps_rcvbyte', 0)
            tcp_server_sent, tcp_client_recv = server_stats.get('tcps_sndbyte', 0), client_stats.get('tcps_rcvbyte', 0)

            udp_client_sent, udp_server_recv = client_stats.get('udps_sndbyte', 0), server_stats.get('udps_rcvbyte', 0)
            udp_server_sent, udp_client_recv = server_stats.get('udps_sndbyte', 0), client_stats.get('udps_rcvbyte', 0)

            assert (tcp_client_sent == tcp_server_recv), 'Too much TCP drops - clients sent: %s, servers received: %s' % (tcp_client_sent, tcp_server_recv)
            assert (tcp_server_sent == tcp_client_recv), 'Too much TCP drops - servers sent: %s, clients received: %s' % (tcp_server_sent, tcp_client_recv)

            assert (udp_client_sent == udp_server_recv), 'Too much UDP drops - clients sent: %s, servers received: %s' % (udp_client_sent, udp_server_recv)
            assert (udp_server_sent == udp_client_recv), 'Too much UDP drops - servers sent: %s, clients received: %s' % (udp_server_sent, udp_client_recv)


        except TRexError as e:
            passed = False
            print(e)

        except AssertionError as e:
            passed = False
            print(e)

        if passed:
            print('\nTest has passed :-)\n')
        else:
            print('\nTest has failed :-(\n')
            sys.exit(1)
