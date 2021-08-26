# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime

import os
from trex.astf.api import *

from base_test import *
from fabric_test import *
from ptf.testutils import group
from trex_test import TRexAstfTest
from trex_utils import list_port_status
from xnt import analyze_report_pcap


TRAFFIC_MULT = 1.0
TEST_DURATION = 10
CAPTURE_LIMIT = 20

SENDER_PORTS = [0]
RECEIVER_PORTS = [1]
INT_COLLECTOR_PORTS = [2]

SIZE = 1
LOOP = 10
WIN = 32
MSS = 0


class AstfTcpFlow(TRexAstfTest, SlicingTest):
    @autocleanup
    def runTest(self):

        passed = True

        try:
            # load ASTF profile
            profile_path = '/fabric-tna/ptf/tests/linerate/http_eflow2.py'

            profile_tunables = {'size': SIZE, 'loop': LOOP, 'win': WIN, 'mss': MSS}
            self.trex_client.load_profile(profile = profile_path, tunables = profile_tunables)

            print("Injecting with multiplier of '%s' for %s seconds" % (TRAFFIC_MULT, TEST_DURATION))
            self.trex_client.start(mult = TRAFFIC_MULT, duration = TEST_DURATION)

            # block until done
            self.trex_client.wait_on_traffic()

            # read the stats after the test
            stats = self.trex_client.get_stats()

            # use this for debug info on all the stats
            print(stats)

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
