from ptf import testutils
# from fabric_test import IntTest

# Connect to the TRex daemon client
# Define packets to be sent
# Tell TRex to send traffic
# Parse results of traffic
# Verify results via assertion
# Close client connection

class TRexTest():

    def setUp():
        self.trex_client = STLClient(server=testutils.test_param_get("trex_server_addr"))

    def tearDown():
        pass
        # cleanup

class IntSingleFlow(IntTest, TRexTest):
    """
    IntTest with line rate traffic
    """
    def runTest(self):
        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        self.runIPv4UnicastTest(
            pkt=pkt,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            with_another_pkt_later=True,
            ig_port=ig_port,
            eg_port=eg_port,
            no_send=True,
        )

        # generate traffic
        # collect result
        # verify
