# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

import pprint

import qos_utils
from trex.astf.api import *
from base_test import *
from fabric_test import *
from trex_test import TRexAstfTest
from qos_tests import QosBaseTest
from trex_utils import monitor_port_stats

# General test parameter
TRAFFIC_MULT = 1
TEST_DURATION = 15
RESPONSE_SIZE = 900
RESPONSE_LOOP = 900_000

# Port setup
UNSHAPED_SENDER_PORT = 1
UNSHAPED_RECEIVER_PORT = 0

REQUEST = b'foo'


class TcpSanity(QosBaseTest, TRexAstfTest):
    def calc_loops (self,buffer,loops):
        max_mul = int(round(0xffffffff/buffer)/4)
        div = loops/max_mul;
        if div<1.0:
            return (loops*buffer,0,0)

        res = (max_mul*buffer,int(div),loops-(int(div)*max_mul))
        expected = buffer*loops
        assert(expected==res[0]*res[1]+buffer*res[2])
        return (res)

    # FIXME: currently skip first 7 seconds of rates due to TRex TCP ramp-up time
    def calc_avg_bps (self, rates: list) -> float:
        avg = 0
        for rate in rates[7:]:
           avg += rate

        return avg / len(rates[7:])


# Not executed by default, requires running Trex in ASTF mode:
#   TREX_PARAMS="--trex-astf-mode" ./ptf/run/hw/linerate fabric TEST=tcp_sanity
class TcpSanityUnshaped(TcpSanity):
    """
    This test generates a single flow of TCP traffic. The purpose of this test
    is to verify whether TRex can generate an iPerf-like single flow of TCP that
    can saturate a link on a switch with unshaped ports.
    """

    def create_profile(self) -> ASTFProfile: 

        response = '*'*RESPONSE_SIZE*1024
        bsize = len(response)

        r = self.calc_loops (bsize,RESPONSE_LOOP)

        # define client behavior
        prog_c = ASTFProgram()
        prog_c.send(REQUEST)

        if r[1]==0:
          prog_c.recv(r[0])
        else:
            prog_c.set_var("var1",r[1]); # set var1 to number of loops
            prog_c.set_label("a:");
            prog_c.recv(r[0],True)
            prog_c.jmp_nz("var1","a:") # dec var1; if not zero, jump back to a: and receive again
            if r[2]:
               prog_c.recv(bsize*r[2])

        # define server behavior
        prog_s = ASTFProgram()
        prog_s.recv(len(REQUEST))
        prog_s.set_send_blocking(False) # continue to the next send while the queue has space 
        prog_s.set_var("var2",RESPONSE_LOOP-1); # set to loop-1 because there is another blocking send
        prog_s.set_label("a:");
        prog_s.send(response)
        prog_s.jmp_nz("var2","a:") # dec var2; if not zero, jump back to a: and send again
        prog_s.set_send_blocking(True) # back to blocking mode 
        prog_s.send(response)

        # tune TCP
        info = ASTFGlobalInfo()
        info.tcp.initwnd = 20
        info.tcp.mss = 9000
        info.tcp.no_delay = 1
        info.tcp.rxbufsize = 1024*1024*1024 # 1G window
        info.tcp.txbufsize = 1024*1024*1024

        # define IP generator for client and server
        ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        # define templates for client and server
        dst_port = qos_utils.L4_DPORT_CONTROL_TRAFFIC
        assoc = ASTFAssociationRule(port=dst_port)
        temp_c = ASTFTCPClientTemplate(program=prog_c, port=dst_port, ip_gen=ip_gen, cps=1, limit=1)
        temp_s = ASTFTCPServerTemplate(program=prog_s, assoc=assoc)
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s, tg_name="control_traffic")

        # create profile
        profile = ASTFProfile(
            default_ip_gen=ip_gen,
            templates=template,
            default_c_glob_info=info,
            default_s_glob_info=info,
        )

        return profile

    @autocleanup
    def runTest(self):
        self.push_chassis_config(with_shaping=False)

        # set up bidirectional forwarding for only ports 1 and 2
        self.setup_port(self.port1, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port2, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port1)
        self.add_forwarding_acl_set_output_port(self.port1, ig_port=self.port2)

        # load astf profile
        self.trex_client.load_profile(profile = self.create_profile())
        self.trex_client.clear_stats()

        # generate TCP traffic
        print("Injecting with multiplier of '%s' for %s seconds" % (TRAFFIC_MULT, TEST_DURATION))
        self.trex_client.start(
            mult = TRAFFIC_MULT, duration = TEST_DURATION, client_mask=1, nc=True,
        )
        results = monitor_port_stats(self.trex_client)

        stats = self.trex_client.get_stats()
        pprint.pp(stats)

        # verify results
        self.assertAlmostEqual(
            self.calc_avg_bps(results[UNSHAPED_SENDER_PORT]["tx_bps"]) / 1000_000_000,
            3.7, # Gbps tput
            delta=0.01,
            msg="Server did not transmit the expected amount of average throughput",
        )
        self.assertAlmostEqual(
            self.calc_avg_bps(results[UNSHAPED_RECEIVER_PORT]["rx_bps"]) / 1000_000_000,
            3.7, # Gbps tput
            delta=0.01,
            msg="Client did not receive the expected amount of average throughput",
        )
