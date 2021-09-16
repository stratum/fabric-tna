# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from datetime import datetime
import pprint

import qos_utils
from trex.astf.api import *
from base_test import *
from fabric_test import *
from trex_test import TRexAstfTest
from qos_tests import QosBaseTest
from trex_utils import list_port_status
from xnt import analyze_report_pcap

# Test specs
TRAFFIC_MULT = 100000.0
TEST_DURATION = 60

# TCP tunables
SIZE = 9000
LOOP = 90
MSS = 0

RECEIVER_PORT = 1

http_req = b'GET /3384 HTTP/1.1\r\nHost: 22.0.0.3\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\nAccept: */*\r\nAccept-Language: en-us\r\nAccept-Encoding: gzip, deflate, compress\r\n\r\n'


class AstfTcpFlow(QosBaseTest, TRexAstfTest):
    """
    TODO: pydoc
    """

    def create_profile(self, size, loop, mss) -> ASTFProfile: 

        http_response = 'HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/6.0\r\nContent-Type: text/html\r\nContent-Length: 32000\r\n\r\n<html><pre>'+('*'*size*1024)+'</pre></html>'

        bsize = len(http_response)

        # client commands
        prog_c = ASTFProgram()
        prog_c.send(http_req)
        prog_c.recv(bsize*loop)

        # server commands
        prog_s = ASTFProgram()
        prog_s.recv(len(http_req))
        prog_s.set_var("var2",loop); # set var 0 to 10 
        prog_s.set_label("a:");
        prog_s.send(http_response)
        prog_s.jmp_nz("var2","a:") # dec var "var2". in case it is *not* zero jump a:

        # Showcase TCP tuning
        info = ASTFGlobalInfo()
        if mss:
          info.tcp.mss = mss
        info.tcp.initwnd = 20  # start big
        info.tcp.no_delay = 1   # to get fast feedback for acks
        info.tcp.rxbufsize = 1024*1024  # 1MB window 
        info.tcp.txbufsize = 1024*1024  
        # info.tcp.do_rfc1323 =1

        # Avoid KEEPALIVE timout
        # keep alive is much longer in sec time 128sec
        info.tcp.keepinit = 5000
        info.tcp.keepidle = 5000
        info.tcp.keepintvl = 5000


        # define IP generators
        ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq")
        ip_gen = ASTFIPGen(
            glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"), dist_client=ip_gen_c, dist_server=ip_gen_s
        )

        # define template
        dst_port = qos_utils.L4_DPORT_CONTROL_TRAFFIC
        temp_c = ASTFTCPClientTemplate(
            program=prog_c, port=dst_port, ip_gen=ip_gen, cps=1, limit=500000
        )
        assoc = ASTFAssociationRule(port=dst_port)
        temp_s = ASTFTCPServerTemplate(program=prog_s, assoc=assoc)
        template = ASTFTemplate(
            client_template=temp_c, server_template=temp_s, tg_name="control_traffic"
        )

        profile = ASTFProfile(
            default_ip_gen=ip_gen,
            templates=template,
            default_c_glob_info=info,
            default_s_glob_info=info,
        )

        return profile

    @autocleanup
    def runTest(self):

        # Set up bidirectional forwarding for only ports 1 and 2
        self.setup_port(self.port1, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.setup_port(self.port2, DEFAULT_VLAN, PORT_TYPE_EDGE)
        self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port1)
        self.add_forwarding_acl_set_output_port(self.port1, ig_port=self.port2)

        # Load astf profile
        profile_tunables = {'size': SIZE, 'loop': LOOP, 'mss': MSS}
        self.trex_client.load_profile(profile = self.create_profile(**profile_tunables))
        self.trex_client.clear_stats()

        # Generate TCP traffic
        print("Injecting with multiplier of '%s' for %s seconds" % (TRAFFIC_MULT, TEST_DURATION))
        self.trex_client.start(
            mult = TRAFFIC_MULT, duration = TEST_DURATION, client_mask=3, nc=True
        )
        self.trex_client.wait_on_traffic()

        stats = self.trex_client.get_stats()
        pprint.pp(stats)

        names = self.trex_client.get_tg_names()
        pprint.pp(names)
        tg_stats = self.trex_client.get_traffic_tg_stats(names)
        pprint.pp(tg_stats)

        if self.trex_client.get_warnings():
            print('\n\n*** test had warnings ****\n\n')
            for w in self.trex_client.get_warnings():
                print(w)

        client_stats = stats['traffic']['client']
        server_stats = stats['traffic']['server']

        # Verify results
        tcp_client_sent, tcp_server_recv = client_stats.get('tcps_sndbyte', 0), server_stats.get('tcps_rcvbyte', 0)
        tcp_server_sent, tcp_client_recv = server_stats.get('tcps_sndbyte', 0), client_stats.get('tcps_rcvbyte', 0)

        udp_client_sent, udp_server_recv = client_stats.get('udps_sndbyte', 0), server_stats.get('udps_rcvbyte', 0)
        udp_server_sent, udp_client_recv = server_stats.get('udps_sndbyte', 0), client_stats.get('udps_rcvbyte', 0)

        assert (tcp_client_sent == tcp_server_recv), 'Too much TCP drops - clients sent: %s, servers received: %s' % (tcp_client_sent, tcp_server_recv)
        assert (tcp_server_sent == tcp_client_recv), 'Too much TCP drops - servers sent: %s, clients received: %s' % (tcp_server_sent, tcp_client_recv)

        assert (udp_client_sent == udp_server_recv), 'Too much UDP drops - clients sent: %s, servers received: %s' % (udp_client_sent, udp_server_recv)
        assert (udp_server_sent == udp_client_recv), 'Too much UDP drops - servers sent: %s, clients received: %s' % (udp_server_sent, udp_client_recv)
