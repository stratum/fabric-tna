# Copyright 2013-present Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

from unittest import skip

from ptf.testutils import group
from scapy.layers.ppp import PPPoED

from base_test import autocleanup, tvsetup
from fabric_test import *

vlan_confs = {
    "tag->tag": [True, True],
    "untag->untag": [False, False],
    "tag->untag": [True, False],
    "untag->tag": [False, True],
}


class FabricBridgingTest(BridgingTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, tagged1, tagged2, pkt, tc_name):
        self.runBridgingTest(tagged1, tagged2, pkt)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                pktlen = 120
                tc_name = pkt_type + "_VLAN_" + vlan_conf + "_" + str(pktlen)
                print "Testing %s packet with VLAN %s.." % (pkt_type, vlan_conf)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    pktlen=pktlen)
                self.doRunTest(tagged[0], tagged[1], pkt, tc_name=tc_name)


@skip("XConnect Currently Unsupported")
@group("xconnect")
class FabricDoubleVlanXConnectTest(DoubleVlanXConnectTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tc_name):
        self.runXConnectTest(pkt)

    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp"]:
            pktlen = 120
            tc_name = pkt_type + "_" + str(pktlen)
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                pktlen=pktlen)
            self.doRunTest(pkt, tc_name=tc_name)


@group("multicast")
class FabricArpBroadcastUntaggedTest(ArpBroadcastTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[],
            untagged_ports=[self.port1, self.port2, self.port3])


@group("multicast")
class FabricArpBroadcastTaggedTest(ArpBroadcastTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port1, self.port2, self.port3],
            untagged_ports=[])


@group("multicast")
class FabricArpBroadcastMixedTest(ArpBroadcastTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port2, self.port3],
            untagged_ports=[self.port1])


class FabricIPv4UnicastTest(IPv4UnicastTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, mac_dest, tagged1, tagged2, tc_name):
        self.runIPv4UnicastTest(
            pkt, mac_dest, prefix_len=24, tagged1=tagged1, tagged2=tagged2)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                tc_name = pkt_type + "_VLAN_" + vlan_conf
                print "Testing %s packet with VLAN %s..." \
                      % (pkt_type, vlan_conf)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, HOST2_MAC, tagged[0], tagged[1], tc_name=tc_name)


class FabricIPv4UnicastGtpPassthroughTest(IPv4UnicastTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        # Assert that GTP packets not meant to be processed by spgw.p4 are
        # forwarded using the outer IP+UDP headers.
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = Ether(src=HOST1_MAC, dst=SWITCH_MAC) / \
              IP(src=HOST3_IPV4, dst=HOST4_IPV4) / \
              UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT) / \
              GTPU(teid=0xeeffc0f0) / \
              IP(src=HOST1_IPV4, dst=HOST2_IPV4) / \
              inner_udp
        self.runIPv4UnicastTest(pkt, next_hop_mac=HOST2_MAC)


class FabricIPv4UnicastGroupTest(FabricTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)

        pkt_from1 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63)
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63)

        self.send_packet(self.port1, str(pkt_from1))
        self.verify_any_packet_any_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPortTcpSport(FabricTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values. In this case tcp-source-port
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # tcpsport_toport list is used to learn the tcp_source_port that
        # causes the packet to be forwarded for each port
        tcpsport_toport = [None, None]
        for i in range(50):
            test_tcp_sport = 1230 + i
            pkt_from1 = testutils.simple_tcp_packet(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_sport=test_tcp_sport)
            exp_pkt_to2 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=test_tcp_sport)
            exp_pkt_to3 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=test_tcp_sport)
            self.send_packet(self.port1, str(pkt_from1))
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            tcpsport_toport[out_port_indx] = test_tcp_sport

        pkt_toport2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_sport=tcpsport_toport[0])
        pkt_toport3 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_sport=tcpsport_toport[1])
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=tcpsport_toport[0])
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=tcpsport_toport[1])
        self.send_packet(self.port1, str(pkt_toport2))
        self.send_packet(self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPortTcpDport(FabricTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values. In this case tcp-dst-port
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # tcpdport_toport list is used to learn the tcp_destination_port that
        # causes the packet to be forwarded for each port
        tcpdport_toport = [None, None]
        for i in range(50):
            test_tcp_dport = 1230 + 3 * i
            pkt_from1 = testutils.simple_tcp_packet(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_dport=test_tcp_dport)
            exp_pkt_to2 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=test_tcp_dport)
            exp_pkt_to3 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=test_tcp_dport)
            self.send_packet(self.port1, str(pkt_from1))
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            tcpdport_toport[out_port_indx] = test_tcp_dport

        pkt_toport2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_dport=tcpdport_toport[0])
        pkt_toport3 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_dport=tcpdport_toport[1])
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=tcpdport_toport[0])
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=tcpdport_toport[1])
        self.send_packet(self.port1, str(pkt_toport2))
        self.send_packet(self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPortIpSrc(FabricTest):

    @tvsetup
    @autocleanup
    def IPv4UnicastGroupTestAllPortL4SrcIp(self, pkt_type):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values and we have an ECMP-like distribution.
        # In this case IP source for tcp and udp packets
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # ipsource_toport list is used to learn the ip_src that causes the packet
        # to be forwarded for each port
        ipsource_toport = [None, None]
        for i in range(50):
            test_ipsource = "10.0.1." + str(i)
            pkt_from1 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=test_ipsource, ip_dst=HOST2_IPV4, ip_ttl=64)
            exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=test_ipsource, ip_dst=HOST2_IPV4, ip_ttl=63)
            exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=test_ipsource, ip_dst=HOST2_IPV4, ip_ttl=63)
            self.send_packet(self.port1, str(pkt_from1))
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            ipsource_toport[out_port_indx] = test_ipsource

        pkt_toport2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=ipsource_toport[0], ip_dst=HOST2_IPV4, ip_ttl=64)
        pkt_toport3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=ipsource_toport[1], ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=ipsource_toport[0], ip_dst=HOST2_IPV4, ip_ttl=63)
        exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=ipsource_toport[1], ip_dst=HOST2_IPV4, ip_ttl=63)
        self.send_packet(self.port1, str(pkt_toport2))
        self.send_packet(self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4SrcIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4SrcIp("udp")


class FabricIPv4UnicastGroupTestAllPortIpDst(FabricTest):

    @tvsetup
    @autocleanup
    def IPv4UnicastGroupTestAllPortL4DstIp(self, pkt_type):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values and we have an ECMP-like distribution.
        # In this case IP dest for tcp and udp packets
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # ipdst_toport list is used to learn the ip_dst that causes the packet
        # to be forwarded for each port
        ipdst_toport = [None, None]
        for i in range(50):
            # If we increment test_ipdst by 1 on hardware, all 50 packets hash to
            # the same ECMP group member and the test fails. Changing the increment
            # to 3 makes this not happen. This seems extremely unlikely and needs
            # further testing to confirm. A similar situation seems to be happening
            # with FabricIPv4UnicastGroupTestAllPortTcpDport
            test_ipdst = "10.0.2." + str(3 * i)
            pkt_from1 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4, ip_dst=test_ipdst, ip_ttl=64)
            exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4, ip_dst=test_ipdst, ip_ttl=63)
            exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4, ip_dst=test_ipdst, ip_ttl=63)
            self.send_packet(self.port1, str(pkt_from1))
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            ipdst_toport[out_port_indx] = test_ipdst

        pkt_toport2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[0], ip_ttl=64)
        pkt_toport3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[1], ip_ttl=64)
        exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[0], ip_ttl=63)
        exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[1], ip_ttl=63)
        self.send_packet(self.port1, str(pkt_toport2))
        self.send_packet(self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4DstIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4DstIp("udp")


class FabricIPv4MPLSTest(FabricTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 400)
        mpls_label = 0xaba
        self.add_next_mpls_routing(
            400, self.port2, SWITCH_MAC, HOST2_MAC, mpls_label)
        self.set_egress_vlan_pop(self.port2, vlan_id)

        pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_1to2 = testutils.simple_mpls_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            mpls_tags=[{
                "label": mpls_label,
                "tc": 0,
                "s": 1,
                "ttl": DEFAULT_MPLS_TTL}],
            inner_frame=pkt_1to2[IP:])

        self.send_packet(self.port1, str(pkt_1to2))
        self.verify_packets(exp_pkt_1to2, [self.port2])


class FabricIPv4MplsGroupTest(IPv4UnicastTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, mac_dest, tagged1, tc_name):
        self.runIPv4UnicastTest(
            pkt, mac_dest, prefix_len=24, tagged1=tagged1, tagged2=False,
            mpls=True)

    def runTest(self):
        print ""
        for tagged1 in [True, False]:
            for pkt_type in ["tcp", "udp", "icmp"]:
                tc_name = pkt_type + "_tagged_" + str(tagged1)
                print "Testing %s packet with tagged=%s..." \
                      % (pkt_type, tagged1)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, HOST2_MAC, tagged1, tc_name=tc_name)


class FabricMplsSegmentRoutingTest(MplsSegmentRoutingTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, mac_dest, next_hop_spine, tc_name):
        self.runMplsSegmentRoutingTest(pkt, mac_dest, next_hop_spine)

    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp"]:
            for next_hop_spine in [True, False]:
                tc_name = pkt_type + "_next_hop_spine_" + str(next_hop_spine)
                print "Testing %s packet, next_hop_spine=%s..." \
                      % (pkt_type, next_hop_spine)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, HOST2_MAC, next_hop_spine, tc_name=tc_name)


@group("packetio")
class FabricArpPacketOutTest(PacketOutTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=MIN_PKT_LEN)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricShortIpPacketOutTest(PacketOutTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=MIN_PKT_LEN)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricLongIpPacketOutTest(PacketOutTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricArpPacketInTest(PacketInTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=MIN_PKT_LEN)
        self.runPacketInTest(pkt, ETH_TYPE_ARP)


@group("packetio")
class FabricLongIpPacketInTest(PacketInTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4)


@group("packetio")
class FabricShortIpPacketInTest(PacketInTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=MIN_PKT_LEN)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4)


@group("packetio")
class FabricTaggedPacketInTest(PacketInTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(dl_vlan_enable=True, vlan_vid=10, pktlen=160)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4, tagged=True, vlan_id=10)


@group("packetio")
class FabricDefaultVlanPacketInTest(FabricTest):

    @tvsetup
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_eth_packet(pktlen=MIN_PKT_LEN)
        self.add_forwarding_acl_punt_to_cpu(eth_type=pkt[Ether].type)
        for port in [self.port1, self.port2]:
            self.send_packet(port, str(pkt))
            self.verify_packet_in(pkt, port)
        self.verify_no_other_packets()


@group("spgw")
class FabricSpgwDownlinkTest(SpgwSimpleTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged1, tagged2, mpls, tc_name):
        self.runDownlinkTest(pkt=pkt, tagged1=tagged1,
                             tagged2=tagged2, mpls=mpls)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for mpls in [False, True]:
                    if mpls and tagged[1]:
                        continue
                    tc_name = "VLAN_" + vlan_conf + "_" + pkt_type + "_mpls_" + str(mpls)
                    print "Testing VLAN=%s, pkt=%s, mpls=%s..." \
                          % (vlan_conf, pkt_type, mpls)
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                        ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                        pktlen=MIN_PKT_LEN
                    )
                    self.doRunTest(pkt, tagged[0], tagged[1], mpls, tc_name=tc_name)


@group("spgw")
class FabricSpgwUplinkTest(SpgwSimpleTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged1, tagged2, mpls):
        self.runUplinkTest(ue_out_pkt=pkt, tagged1=tagged1,
                           tagged2=tagged2, mpls=mpls)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for mpls in [False, True]:
                    if mpls and tagged[1]:
                        continue
                    print "Testing VLAN=%s, pkt=%s, mpls=%s..." \
                          % (vlan_conf, pkt_type, mpls)
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                        ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                        pktlen=MIN_PKT_LEN
                    )
                    self.doRunTest(pkt, tagged[0], tagged[1], mpls)

@group("int")
@group("spgw")
class FabricSpgwUplinkIntTest(SpgwIntTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, vlan_conf, tagged, pkt_type, mpls):
        print "Testing VLAN=%s, pkt=%s, mpls=%s" \
              % (vlan_conf, pkt_type, mpls)
        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
        self.runSpgwUplinkIntTest(pkt=pkt, tagged1=tagged[0],
                                  tagged2=tagged[1], mpls=mpls)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp", "tcp", "icmp"]:
                for mpls in [False, True]:
                    if mpls and tagged[1]:
                        continue
                    self.doRunTest(vlan_conf, tagged, pkt_type, mpls)

@group("int")
@group("spgw")
class FabricSpgwDownlinkIntTest(SpgwIntTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, vlan_conf, tagged, pkt_type, mpls):
        print "Testing VLAN=%s, pkt=%s, mpls=%s..." \
              % (vlan_conf, pkt_type, mpls)
        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
        self.runSpgwDownlinkIntTest(pkt=pkt, tagged1=tagged[0],
                                    tagged2=tagged[1], mpls=mpls)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp", "tcp", "icmp"]:
                for mpls in [False, True]:
                    if mpls and tagged[1]:
                        continue
                    self.doRunTest(vlan_conf, tagged, pkt_type, mpls)

@group("int")
class FabricIntTest(IntTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, vlan_conf, tagged, pkt_type, mpls):
        print "Testing VLAN=%s, pkt=%s, mpls=%s..." \
              % (vlan_conf, pkt_type, mpls)
        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
        self.runIntTest(pkt=pkt,
                        tagged1=tagged[0],
                        tagged2=tagged[1],
                        mpls=mpls)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp", "tcp", "icmp"]:
                for mpls in [False, True]:
                    if mpls and tagged[1]:
                        continue
                    self.doRunTest(vlan_conf, tagged, pkt_type, mpls)

@group("bng")
class FabricPppoeUpstreamTest(PppoeTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged2, mpls, line_enabled):
        self.runUpstreamV4Test(pkt, tagged2, mpls, line_enabled)

    def runTest(self):
        print ""
        for line_enabled in [True, False]:
            for out_tagged in [False, True]:
                for mpls in [False, True]:
                    if mpls and out_tagged:
                        continue
                    for pkt_type in ["tcp", "udp", "icmp"]:
                        print "Testing %s packet, line_enabled=%s, " \
                              "out_tagged=%s, mpls=%s ..." \
                              % (pkt_type, line_enabled, out_tagged, mpls)
                        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                            pktlen=120)
                        self.doRunTest(pkt, out_tagged, mpls, line_enabled)


@group("bng")
class FabricPppoeControlPacketInTest(PppoeTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, line_mapped):
        self.runControlPacketInTest(pkt, line_mapped)

    def runTest(self):
        # FIXME: using a dummy payload will generate malformed PPP packets,
        #  instead we should use appropriate PPP protocol values and PPPoED
        #  payload (tags)
        # https://www.cloudshark.org/captures/f79aea31ad53
        pkts = {
            "PADI": Ether(src=HOST1_MAC, dst=BROADCAST_MAC) / \
                    PPPoED(version=1, type=1, code=PPPOED_CODE_PADI) / \
                    "dummy pppoed payload",
            "PADR": Ether(src=HOST1_MAC, dst=SWITCH_MAC) / \
                    PPPoED(version=1, type=1, code=PPPOED_CODE_PADR) / \
                    "dummy pppoed payload",
        }

        print ""
        for line_mapped in [True, False]:
            for pkt_type, pkt in pkts.items():
                print "Testing %s packet, line_mapped=%s..." \
                      % (pkt_type, line_mapped)
                self.doRunTest(pkt, line_mapped)


@group("bng")
class FabricPppoeControlPacketOutTest(PppoeTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt):
        self.runControlPacketOutTest(pkt)

    def runTest(self):
        # FIXME: using a dummy payload will generate malformed PPP packets,
        #  instead we should use appropriate PPP protocol values and PPPoED
        #  payload (tags)
        # https://www.cloudshark.org/captures/f79aea31ad53
        pkts = {
            "PADO": Ether(src=SWITCH_MAC, dst=HOST1_MAC) / \
                    PPPoED(version=1, type=1, code=PPPOED_CODE_PADO) / \
                    "dummy pppoed payload",
            "PADS": Ether(src=SWITCH_MAC, dst=HOST1_MAC) / \
                    PPPoED(version=1, type=1, code=PPPOED_CODE_PADS) / \
                    "dummy pppoed payload"
        }

        print ""
        for pkt_type, pkt in pkts.items():
            print "Testing %s packet..." % pkt_type
            self.doRunTest(pkt)


@group("bng")
class FabricPppoeDownstreamTest(PppoeTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, in_tagged, line_enabled):
        self.runDownstreamV4Test(pkt, in_tagged, line_enabled)

    def runTest(self):
        print ""
        for line_enabled in [True, False]:
            for in_tagged in [False, True]:
                for pkt_type in ["tcp", "udp", "icmp"]:
                    print "Testing %s packet, line_enabled=%s, " \
                          "in_tagged=%s..." \
                          % (pkt_type, line_enabled, in_tagged)
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        pktlen=120)
                    self.doRunTest(pkt, in_tagged, line_enabled)


@group("dth")
class FabricDoubleTaggedHostUpstream(DoubleVlanTerminationTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, out_tagged, mpls):
        self.runPopAndRouteTest(pkt, next_hop_mac=HOST2_MAC,
                                vlan_id=VLAN_ID_1, inner_vlan_id=VLAN_ID_2,
                                out_tagged=out_tagged, mpls=mpls)

    def runTest(self):
        print ""
        for out_tagged in [True, False]:
            for mpls in [True, False]:
                if mpls and out_tagged:
                    continue
                for pkt_type in ["tcp", "udp", "icmp"]:
                    print "Testing %s packet, out_tagged=%s..." \
                          % (pkt_type, out_tagged)
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        pktlen=120)
                    self.doRunTest(pkt, out_tagged, mpls)


@group("dth")
class FabricDoubleTaggedHostDownstream(DoubleVlanTerminationTest):

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, in_tagged):
        self.runRouteAndPushTest(pkt, next_hop_mac=HOST2_MAC,
                                 next_vlan_id=VLAN_ID_1, next_inner_vlan_id=VLAN_ID_2,
                                 in_tagged=in_tagged)

    def runTest(self):
        print ""
        for in_tagged in [True, False]:
            for pkt_type in ["tcp", "udp", "icmp"]:
                print "Testing %s packet, in_tagged=%s..." \
                      % (pkt_type, in_tagged)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    pktlen=120)
                self.doRunTest(pkt, in_tagged)

@group("p4rt")
class TableEntryReadWriteTest(FabricTest):

    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_bridging_entry(1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 1)
        expected_bridging_entry = req.updates[0].entity.table_entry
        received_bridging_entry = self.read_bridging_entry(1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff")
        self.verify_p4runtime_entity(expected_bridging_entry, received_bridging_entry)

        req, _ = self.add_forwarding_acl_punt_to_cpu(ETH_TYPE_IPV4)
        expected_acl_entry = req.updates[0].entity.table_entry
        received_acl_entry = self.read_forwarding_acl_punt_to_cpu(ETH_TYPE_IPV4)
        self.verify_p4runtime_entity(expected_acl_entry, received_acl_entry)

    def runTest(self):
        print("")
        self.doRunTest()

@group("p4rt")
class ActionProfileMemberReadWriteTest(FabricTest):

    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_next_hashed_group_member("output_hashed", [("port_num", stringify(1, 2))])
        expected_action_profile_member = req.updates[0].entity.action_profile_member
        mbr_id = expected_action_profile_member.member_id
        received_action_profile_member = self.read_next_hashed_group_member(mbr_id)
        self.verify_p4runtime_entity(expected_action_profile_member, received_action_profile_member)

    def runTest(self):
        print("")
        self.doRunTest()

@group("p4rt")
class ActionProfileGroupReadWriteTest(FabricTest):

    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_next_hashed_group_member("output_hashed", [("port_num", stringify(1, 2))])
        member_installed = req.updates[0].entity.action_profile_member
        mbr_id = member_installed.member_id

        grp_id = 1
        req, _ = self.add_next_hashed_group(grp_id, [mbr_id])
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        self.verify_next_hashed_group(grp_id, expected_action_profile_group)

    def runTest(self):
        print("")
        self.doRunTest()

@group("p4rt")
class ActionProfileGroupModificationTest(FabricTest):

    @tvsetup
    @autocleanup
    def doRunTest(self):
        # Insert members
        mbr_ids = []
        for port_num in range(1, 4):
            req, _ = self.add_next_hashed_group_member("output_hashed", [("port_num", stringify(port_num, 2))])
            member_installed = req.updates[0].entity.action_profile_member
            mbr_ids.append(member_installed.member_id)

        # Insert group with member-1 and member-2
        grp_id = 1
        req, _ = self.add_next_hashed_group(grp_id, mbr_ids[:2])
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        received_action_profile_group = self.read_next_hashed_group(grp_id)
        self.verify_p4runtime_entity(expected_action_profile_group, received_action_profile_group)

        # Modify group with member-2 and member-3
        req, _ = self.modify_next_hashed_group(grp_id, mbr_ids[1:], grp_size=2)
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        received_action_profile_group = self.read_next_hashed_group(grp_id)
        self.verify_p4runtime_entity(expected_action_profile_group, received_action_profile_group)

    def runTest(self):
        print("")
        self.doRunTest()

@group("p4rt")
class MulticastGroupReadWriteTest(FabricTest):

    @tvsetup
    @autocleanup
    def doRunTest(self):
        grp_id = 10
        replicas = [(0, 1), (0, 2), (0, 3)]  # (instance, port)
        req, _ = self.add_mcast_group(grp_id, replicas)
        expected_mc_entry = req.updates[0].entity.packet_replication_engine_entry.multicast_group_entry
        self.verify_mcast_group(grp_id, expected_mc_entry)

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class MulticastGroupModificationTest(FabricTest):

    # Not using the auto cleanup since the Stratum modifies the
    # multicast node table internally
    @tvsetup
    def doRunTest(self):
        # Add group with egress port 1~3 (instance 1 and 2)
        grp_id = 10
        replicas = [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3)]  # (instance, port)
        self.add_mcast_group(grp_id, replicas)

        # Modify the group with egress port 2~4 (instance 2 and 3)
        replicas = [(2, 2), (2, 3), (2, 4), (3, 2), (3, 3), (3, 4)]  # (instance, port)
        req, _ = self.modify_mcast_group(grp_id, replicas)
        expected_mc_entry = req.updates[0].entity.packet_replication_engine_entry.multicast_group_entry
        self.verify_mcast_group(grp_id, expected_mc_entry)

        # Cleanup
        self.delete_mcast_group(grp_id)

    def runTest(self):
        print("")
        self.doRunTest()

@group("p4rt")
class CounterTest(BridgingTest):

    @tvsetup
    @autocleanup
    def doRunTest(self):
        pkt = getattr(testutils, "simple_tcp_packet")(pktlen=120)
        self.runBridgingTest(False, False, pkt)
        # Check direct counters from 'ingress_port_vlan' table
        table_entries = [req.updates[0].entity.table_entry for req in self.reqs
                         if req.updates[0].entity.HasField('table_entry')]
        table_entries = [te for te in table_entries
                         if te.table_id == self.get_table_id('ingress_port_vlan')]

        # Here, both table entries hits once with a
        # simple TCP packet(120 bytes + 2*2 bytes checksum inserted by scapy)
        for table_entry in table_entries:
            self.verify_direct_counter(table_entry, 124, 1)

        # Check that direct counters can be set/cleared.
        for table_entry in table_entries:
            self.write_direct_counter(table_entry, 0, 0)
            self.verify_direct_counter(table_entry, 0, 0)

            self.write_direct_counter(table_entry, 1024, 1024)
            self.verify_direct_counter(table_entry, 1024, 1024)

        try:
            self.get_counter("fwd_type_counter")
        except Exception as ex:
            print("Unable to find indirect counter `fwd_type_counter`, skip")
            return

        # Read indirect counter (fwd_type_counter)
        # Here we are trying to read counter for traffic class "0"
        # which means how many traffic for bridging
        # In the bridging test we sent two TCP packets and both packets
        # are classified as bridging class.
        self.verify_indirect_counter("fwd_type_counter", 0, "BOTH", 248, 2)

    def runTest(self):
        print("")
        self.doRunTest()


# FIXME: remove when will start running TVs on hardware
class FabricIpv4UnicastLoopbackModeTest(IPv4UnicastTest):
    """Emulates TV loopback mode for Ipv4UnicastTest"""

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, next_hop_mac):
        # Since we cannot put interfaces in loopback mode, verify that output
        # packet has fake ether type for loopback...
        self.runIPv4UnicastTest(
            pkt, next_hop_mac=next_hop_mac, prefix_len=24, no_send=True)
        exp_pkt_1 = Ether(type=ETH_TYPE_CPU_LOOPBACK_INGRESS,
                          src=ZERO_MAC, dst=ZERO_MAC) / pkt
        routed_pkt = pkt_decrement_ttl(pkt_route(pkt, next_hop_mac))
        exp_pkt_2 = Ether(type=ETH_TYPE_CPU_LOOPBACK_EGRESS,
                          src=ZERO_MAC, dst=ZERO_MAC) / routed_pkt
        self.send_packet_out(self.build_packet_out(
            pkt, self.port1, cpu_loopback_mode=CPU_LOOPBACK_MODE_INGRESS))
        self.verify_packet(exp_pkt_1, self.port1)
        self.send_packet(self.port1, str(exp_pkt_1))
        self.verify_packet(exp_pkt_2, self.port2)
        self.send_packet(self.port2, str(exp_pkt_2))
        self.verify_packet_in(routed_pkt, self.port2)
        self.verify_no_other_packets()

    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp"]:
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                pktlen=MIN_PKT_LEN
            )
            self.doRunTest(pkt, HOST2_MAC)


# FIXME: remove when will start running TVs on hardware
class FabricPacketInLoopbackModeTest(FabricTest):
    """Emulates TV loopback mode for packet-in tests"""

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged):
        self.add_forwarding_acl_punt_to_cpu(eth_type=pkt[Ether].type)
        if tagged:
            pkt = pkt_add_vlan(pkt, VLAN_ID_1)
        exp_pkt_1 = Ether(type=ETH_TYPE_CPU_LOOPBACK_INGRESS,
                          src=ZERO_MAC, dst=ZERO_MAC) / pkt
        for port in [self.port1, self.port2]:
            if tagged:
                self.set_ingress_port_vlan(port, True, VLAN_ID_1, VLAN_ID_1)
            else:
                self.set_ingress_port_vlan(port, False, 0, VLAN_ID_1)
            self.send_packet_out(self.build_packet_out(
                pkt, port, cpu_loopback_mode=CPU_LOOPBACK_MODE_INGRESS))
            self.verify_packet(exp_pkt_1, port)
            self.send_packet(port, str(exp_pkt_1))
            self.verify_packet_in(pkt, port)
        self.verify_no_other_packets()

    @tvsetup
    @autocleanup
    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp", "arp"]:
            for tagged in [True, False]:
                print "Testing %s packet, tagged=%s..." % (pkt_type, tagged)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, tagged)


# FIXME: remove when will start running TVs on hardware
class FabricPacketOutLoopbackModeTest(FabricTest):
    """Emulates TV loopback mode for packet-out tests"""

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt):
        exp_pkt_1 = Ether(type=ETH_TYPE_CPU_LOOPBACK_EGRESS,
                          src=ZERO_MAC, dst=ZERO_MAC) / pkt
        for port in [self.port1, self.port2]:
            self.send_packet_out(self.build_packet_out(
                pkt, port, cpu_loopback_mode=CPU_LOOPBACK_MODE_DIRECT))
            self.verify_packet(exp_pkt_1, port)
            self.send_packet(port, str(exp_pkt_1))
            self.verify_packet_in(pkt, port)
        self.verify_no_other_packets()

    @tvsetup
    @autocleanup
    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp", "arp"]:
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                pktlen=MIN_PKT_LEN
            )
            self.doRunTest(pkt)
