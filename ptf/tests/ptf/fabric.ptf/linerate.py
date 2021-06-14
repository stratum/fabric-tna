from ptf import testutils
from fabric_test import *
from trex_stl_lib.api import *

# Connect to the TRex daemon client
# Define packets to be sent
# Tell TRex to send traffic
# Parse results of traffic
# Verify results via assertion
# Close client connection

class TRexTest():

    # TODO: what is self?
    def setUp(self):
        # generate a packet for the stream here
        # TODO: create function ot generate a packet
        pkt = self.get_sample_packet(self.args.pkt_type)
        if not pkt:
            return 1

        # create a client process and connect to the server
        self.trex_client = STLClient(server=testutils.test_param_get("trex_server_addr"))

        # create the stream
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())

        # Hook up trex instance
        try:
            self.trex_client.connect()
            self.trex_client.acquire()
            self.trex_client.reset()
            self.trex_client.clear_stats()

        except STLError as e:
            print("Got error for Trex server: {0}".format(e))

        # add the stream to the client and set up the ports
        self.trex_client.add_streams(stream, ports=SENDER_PORTS)

        # set arguments to capture
        # pkt_capture_limit = args.duration * 3
        # self.trex_client.set_service_mode(ports=INT_COLLECTPR_PORTS, enabled=True)
        # capture = self.trex_client.start_capture(
        #     rx_ports=INT_COLLECTPR_PORTS,
        #     limit=pkt_capture_limit,
        #     bpf_filter="udp and dst port 32766",
        # )

        self.trex_client.start(ports=SENDER_PORTS, mult=args.mult, duration=self.args.duration)
        self.trex_client.wait_on_traffic(ports=SENDER_PORTS)
        # output = "/tmp/int-single-flow-{}-{}.pcap".format(
        #     args.pkt_type, datetime.now().strftime("%Y%m%d-%H%M%S")
        # )
        return self.trex_client.get_stats()


    def tearDown(self):
        self.trex_client.stop()
        self.trex_client.release()
        self.trex_client.disconnect()

        # TODO: figure out how to capture correctly
        # self.trex_client.stop_capture(capture["id"], output)
        # analysis_report_pcap(output)
        # list_port_status(self.trex_client.get_stats())

class IntSingleFlow(IntTest, TRexTest):
    """
    IntTest with line rate traffic
    """
    def runTest(self):
        # Set collector, report table, and mirror sessions
        # TODO: why this?
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

        self.setUp()
        self.tearDown()
