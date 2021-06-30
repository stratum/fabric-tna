# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

import importlib
from base_test import *
from trex.stl.api import STLClient, STLError

class TRexTest(BaseTest):
    def __init__(self):
        self.trex_client = None

    def setUp(self):
        # initialize the stateless client
        print('Connecting STLClient to TRex server...')
        self.trex_client = STLClient(ptf.testutils.get_test_args('trex_server_addr'))

        # attempt to connect to trex server
        try:
            self.trex_client.connect()
            self.trex_client.acquire()
            self.trex_client.reset()  # Resets configs from all ports
            self.trex_client.clear_stats()  # Clear status from all ports
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
