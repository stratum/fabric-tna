from lib.base_test import BaseTest
from argparse import ArgumentParser
from trex.stl.api import STLClient, STLError
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.sctp import SCTP
from scapy.layers.vxlan import VXLAN
from scapy.packet import bind_layer

class TRexTest(BaseTest):
    def __init__(self):
        self.trex_client = None

    def setUp(self):
        # initialize the stateless client
        print('Connecting STLClient to TRex server...')
        self.trex_client = STLClient(ptf.testutils.get_test_args('trex_server_addr'))

        # attempt to connect to trex server
        try:
            trex_client.connect()
            trex_client.acquire()
            trex_client.reset()  # Resets configs from all ports
            trex_client.clear_stats()  # Clear status from all ports
        except STLError as e:
            print('Failed connecting to TRex server: {0}'.format(e))
            return False

        return True


    def tearDown(self):
        print('Tearing down STLClient...')
        try:
            self.trex_client.stop()
            self.trex_client.release()
            self.trex_client.disconnect()
        except STLError as e:
            print('Failed tearing down STLClient: {0}'.format(e))
            return False

        return True
