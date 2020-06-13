# Copyright 2013-present Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

from itertools import combinations

from ptf.testutils import group
from scapy.layers.ppp import PPPoED

from base_test import autocleanup, stringify
from fabric_test import *

from unittest import skip

vlan_confs = {
    "tag->tag": [True, True],
    "untag->untag": [False, False],
    "tag->untag": [True, False],
    "untag->tag": [False, True],
}


class FabricBridgingTest(BridgingTest):
    @autocleanup
    def doRunTest(self, tagged1, tagged2, pkt):
        self.runBridgingTest(tagged1, tagged2, pkt)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                print "Testing %s packet with VLAN %s.." % (pkt_type, vlan_conf)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    pktlen=120)
                self.doRunTest(tagged[0], tagged[1], pkt)


@group("xconnect")
class FabricDoubleVlanXConnectTest(DoubleVlanXConnectTest):
    @autocleanup
    def doRunTest(self, pkt):
        self.runXConnectTest(pkt)

    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp"]:
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                pktlen=120)
            self.doRunTest(pkt)


@group("multicast")
class FabricArpBroadcastUntaggedTest(ArpBroadcastTest):
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[],
            untagged_ports=[self.port1, self.port2, self.port3])


@group("multicast")
class FabricArpBroadcastTaggedTest(ArpBroadcastTest):
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port1, self.port2, self.port3],
            untagged_ports=[])


@group("multicast")
class FabricArpBroadcastMixedTest(ArpBroadcastTest):
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port2, self.port3],
            untagged_ports=[self.port1])


class FabricIPv4UnicastTest(IPv4UnicastTest):
    @autocleanup
    def doRunTest(self, pkt, mac_dest, tagged1, tagged2):
        self.runIPv4UnicastTest(
            pkt, mac_dest, prefix_len=24, tagged1=tagged1, tagged2=tagged2)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                print "Testing %s packet with VLAN %s..." \
                      % (pkt_type, vlan_conf)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, HOST2_MAC, tagged[0], tagged[1])


class FabricIPv4UnicastGtpTest(IPv4UnicastTest):
    @autocleanup
    def runTest(self):
        # Assert that GTP packets not meant to be processed by spgw.p4 are
        # forwarded using the outer IP+UDP headers. For spgw.p4 to kick in
        # outer IP dst should be in a subnet defined at compile time (see
        # fabric.p4's parser).
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = Ether(src=HOST1_MAC, dst=SWITCH_MAC) / \
              IP(src=HOST3_IPV4, dst=HOST4_IPV4) / \
              UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT) / \
              GTPU(teid=0xeeffc0f0) / \
              IP(src=HOST1_IPV4, dst=HOST2_IPV4) / \
              inner_udp
        self.runIPv4UnicastTest(pkt, next_hop_mac=HOST2_MAC)


class FabricIPv4UnicastGroupTest(FabricTest):
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

        testutils.send_packet(self, self.port1, str(pkt_from1))
        testutils.verify_any_packet_any_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPortTcpSport(FabricTest):
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
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
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
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPortTcpDport(FabricTest):
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
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
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
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPortIpSrc(FabricTest):
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
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
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
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4SrcIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4SrcIp("udp")


class FabricIPv4UnicastGroupTestAllPortIpDst(FabricTest):
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
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
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
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4DstIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4DstIp("udp")


class FabricIPv4MPLSTest(FabricTest):
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

        testutils.send_packet(self, self.port1, str(pkt_1to2))
        testutils.verify_packets(self, exp_pkt_1to2, [self.port2])


class FabricIPv4MplsGroupTest(IPv4UnicastTest):
    @autocleanup
    def doRunTest(self, pkt, mac_dest, tagged1):
        self.runIPv4UnicastTest(
            pkt, mac_dest, prefix_len=24, tagged1=tagged1, tagged2=False,
            mpls=True)

    def runTest(self):
        print ""
        for tagged1 in [True, False]:
            for pkt_type in ["tcp", "udp", "icmp"]:
                print "Testing %s packet with tagged=%s..." \
                      % (pkt_type, tagged1)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, HOST2_MAC, tagged1)


class FabricMplsSegmentRoutingTest(MplsSegmentRoutingTest):
    @autocleanup
    def doRunTest(self, pkt, mac_dest, next_hop_spine):
        self.runMplsSegmentRoutingTest(pkt, mac_dest, next_hop_spine)

    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp"]:
            for next_hop_spine in [True, False]:
                print "Testing %s packet, next_hop_spine=%s..." \
                      % (pkt_type, next_hop_spine)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, HOST2_MAC, next_hop_spine)


@group("packetio")
class FabricArpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=MIN_PKT_LEN)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricShortIpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=MIN_PKT_LEN)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricLongIpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricArpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=MIN_PKT_LEN)
        self.runPacketInTest(pkt, ETH_TYPE_ARP)


@group("packetio")
class FabricLongIpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4)


@group("packetio")
class FabricShortIpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=MIN_PKT_LEN)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4)


@group("packetio")
class FabricTaggedPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(dl_vlan_enable=True, vlan_vid=10, pktlen=160)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4, tagged=True, vlan_id=10)


@group("packetio")
class FabricDefaultVlanPacketInTest(FabricTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_eth_packet(pktlen=MIN_PKT_LEN)
        self.add_forwarding_acl_punt_to_cpu(eth_type=pkt[Ether].type)
        for port in [self.port1, self.port2]:
            testutils.send_packet(self, port, str(pkt))
            self.verify_packet_in(pkt, port)
        testutils.verify_no_other_packets(self)


@group("spgw")
class SpgwDownlinkTest(SpgwSimpleTest):
    @autocleanup
    def doRunTest(self, pkt, tagged1, tagged2, mpls):
        self.runDownlinkTest(pkt=pkt, tagged1=tagged1,
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


@group("spgw")
class SpgwUplinkTest(SpgwSimpleTest):
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


# @group("spgw")
# @unittest.skip("INT transit capability not yet supported")
# class SpgwDownlinkMPLS_INT_Test(SpgwMPLSTest):
#     @autocleanup
#     def runTest(self):
#         self.setup_int()
#
#         dport = 5060
#
#         # int_type=hop-by-hop
#         int_shim = INT_L45_HEAD(int_type=1, length=4)
#         # ins_cnt: 5 = switch id + ports + q occupancy + ig port + eg port)
#         # max_hop_count: 3
#         # total_hop_count: 0
#         # instruction_mask_0003: 0xd = switch id (0), ports (1), q occupancy (3)
#         # instruction_mask_0407: 0xc = ig timestamp (4), eg timestamp (5)
#         int_header = "\x00\x05\x03\x00\xdc\x00\x00\x00"
#         # IP proto (UDP), UDP dport (4096)
#         int_tail = INT_L45_TAIL(next_proto=17, proto_param=dport)
#
#         payload = "\xab" * 128
#         inner_udp = UDP(sport=5061, dport=dport, chksum=0)
#         # IP tos is 0x04 to enable INT
#         pkt = Ether(src=self.DMAC_2, dst=self.SWITCH_MAC_2) / \
#               IP(tos=0x04, src=S1U_ENB_IPV4, dst=UE_IPV4) / \
#               inner_udp / \
#               int_shim / int_header / int_tail / \
#               payload
#
#         exp_int_shim = INT_L45_HEAD(int_type=1, length=9)
#         # total_hop_count: 1
#         exp_int_header = "\x00\x05\x03\x01\xdc\x00\x00\x00"
#         # switch id: 1
#         exp_int_metadata = "\x00\x00\x00\x01"
#         # ig port: port2, eg port: port2
#         exp_int_metadata += stringify(self.port2, 2) + stringify(self.port1, 2)
#         # q id: 0, q occupancy: ?
#         exp_int_metadata += "\x00\x00\x00\x00"
#         # ig timestamp: ?
#         # eg timestamp: ?
#         exp_int_metadata += "\x00\x00\x00\x00" * 2
#
#         exp_int = exp_int_shim / exp_int_header / exp_int_metadata / int_tail
#
#         exp_pkt = Ether(src=self.SWITCH_MAC_1, dst=self.DMAC_1) / \
#                   MPLS(label=self.mpls_label, cos=0, s=1, ttl=64) / \
#                   IP(tos=0, id=0x1513, flags=0, frag=0,
#                      src=S1U_SGW_IPV4, dst=S1U_ENB_IPV4) / \
#                   UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT, chksum=0) / \
#                   make_gtp(20 + len(inner_udp) + len(exp_int) + len(payload), 1) / \
#                   IP(tos=0x04, src=S1U_ENB_IPV4, dst=UE_IPV4, ttl=64) / \
#                   inner_udp / \
#                   exp_int / \
#                   payload
#         # We mask off the timestamps as well as the queue occupancy
#         exp_pkt = Mask(exp_pkt)
#         offset_metadata = 14 + 4 + 20 + 8 + 8 + 20 + 8 + 4 + 8
#         exp_pkt.set_do_not_care((offset_metadata + 9) * 8, 11 * 8)
#
#         testutils.send_packet(self, self.port2, str(pkt))
#         testutils.verify_packet(self, exp_pkt, self.port1)


@group("int")
class FabricIntSourceTest(IntTest):
    @autocleanup
    def doRunTest(self, **kwargs):
        self.runIntSourceTest(**kwargs)

    def runTest(self):
        instr_sets = [
            [INT_SWITCH_ID, INT_IG_EG_PORT],
            [INT_SWITCH_ID, INT_IG_EG_PORT, INT_IG_TSTAMP, INT_EG_TSTAMP, INT_QUEUE_OCCUPANCY]
        ]
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp", "tcp"]:
                for instrs in instr_sets:
                    print "Testing VLAN=%s, pkt=%s, instructions=%s..." \
                          % (vlan_conf, pkt_type,
                             ",".join([INT_INS_TO_NAME[i] for i in instrs]))
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                    self.doRunTest(pkt=pkt, instructions=instrs,
                                   with_transit=False, ignore_csum=True,
                                   tagged1=tagged[0], tagged2=tagged[1])


@group("int")
class FabricIntSourceAndTransitTest(IntTest):
    @autocleanup
    def doRunTest(self, vlan_conf, tagged, pkt_type, mpls, instrs):
        print "Testing VLAN=%s, pkt=%s, mpls=%s, instructions=%s..." \
              % (vlan_conf, pkt_type, mpls,
                 ",".join([INT_INS_TO_NAME[i] for i in instrs]))
        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
        self.runIntSourceTest(pkt=pkt, instructions=instrs,
                              with_transit=True, ignore_csum=True,
                              tagged1=tagged[0], tagged2=tagged[1], mpls=mpls)

    def runTest(self):
        instr_sets = [
            [INT_SWITCH_ID, INT_IG_EG_PORT],
            [INT_SWITCH_ID, INT_IG_EG_PORT, INT_IG_TSTAMP, INT_EG_TSTAMP,
             INT_QUEUE_OCCUPANCY]
        ]
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp", "tcp"]:
                for mpls in [False, True]:
                    for instrs in instr_sets:
                        if mpls and tagged[1]:
                            continue
                        self.doRunTest(vlan_conf, tagged, pkt_type, mpls,
                                       instrs)


@group("int")
class FabricIntTransitTest(IntTest):
    @autocleanup
    def doRunTest(self, vlan_conf, tagged, pkt_type, prev_hops, instrs, mpls):
        print "Testing VLAN=%s, pkt=%s, mpls=%s, prev_hops=%s, instructions=%s..." \
              % (vlan_conf, pkt_type, mpls, prev_hops,
                 ",".join([INT_INS_TO_NAME[i] for i in instrs]))
        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
        hop_metadata, _ = self.get_int_metadata(instrs, 0xCAFEBABE, 0xDEAD, 0xBEEF)
        int_pkt = self.get_int_pkt(pkt=pkt, instructions=instrs, max_hop=50,
                                   transit_hops=prev_hops,
                                   hop_metadata=hop_metadata)
        self.runIntTransitTest(pkt=int_pkt,
                               tagged1=tagged[0],
                               tagged2=tagged[1],
                               ignore_csum=1, mpls=mpls)

    def runTest(self):
        instr_sets = [
            [INT_SWITCH_ID, INT_IG_EG_PORT],
            [INT_SWITCH_ID, INT_IG_EG_PORT, INT_IG_TSTAMP, INT_EG_TSTAMP, INT_QUEUE_OCCUPANCY]
        ]
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp", "tcp"]:
                for mpls in [False, True]:
                    for prev_hops in [0, 3]:
                        for instrs in instr_sets:
                            if mpls and tagged[1]:
                                continue
                            self.doRunTest(vlan_conf, tagged, pkt_type,
                                           prev_hops, instrs, mpls)


@group("int")
@group("int-full")
class FabricIntTransitFullTest(IntTest):
    @autocleanup
    def doRunTest(self, **kwargs):
        self.runIntTransitTest(**kwargs)

    def runTest(self):
        instr_sets = []
        for num_instr in range(1, len(INT_ALL_INSTRUCTIONS) + 1):
            instr_sets.extend(combinations(INT_ALL_INSTRUCTIONS, num_instr))
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp"]:
                for prev_hops in [0, 3]:
                    for instructions in instr_sets:
                        print "Testing VLAN=%s, pkt=%s, prev_hops=%s, instructions=%s..." \
                              % (vlan_conf, pkt_type, prev_hops,
                                 ",".join([INT_INS_TO_NAME[i] for i in
                                           instructions]))
                        pkt = getattr(testutils,
                                      "simple_%s_packet" % pkt_type)()
                        hop_metadata, _ = self.get_int_metadata(
                            instructions, 0xCAFEBABE, 0xDEAD, 0xBEEF)
                        int_pkt = self.get_int_pkt(
                            pkt=pkt, instructions=instructions, max_hop=50,
                            transit_hops=prev_hops, hop_metadata=hop_metadata)
                        self.doRunTest(
                            pkt=int_pkt, tagged1=tagged[0], tagged2=tagged[1],
                            ignore_csum=1)


@group("bng")
class FabricPppoeUpstreamTest(PppoeTest):

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

@group("p4r-function")
class TableEntryReadWriteTest(FabricTest):

    @autocleanup
    def doRunTest(self):
        req, _ = self.add_bridging_entry(1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 1)
        expected_bridging_entry = req.updates[0].entity.table_entry
        received_bridging_entry = self.read_bridging_entry(1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff")
        self.verify_p4runtime_entity(expected_bridging_entry, received_bridging_entry)

    def runTest(self):
        self.doRunTest()

@group("p4r-function")
class ActionProfileMemberReadWriteTest(FabricTest):

    @autocleanup
    def doRunTest(self):
        req, _ = self.add_next_hashed_group_member("output_hashed", [("port_num", stringify(1, 2))])
        expected_action_profile_member = req.updates[0].entity.action_profile_member
        mbr_id = expected_action_profile_member.member_id
        received_action_profile_member = self.read_next_hashed_group_member(mbr_id)
        self.verify_p4runtime_entity(expected_action_profile_member, received_action_profile_member)

    def runTest(self):
        self.doRunTest()

@group("p4r-function")
class ActionProfileGroupReadWriteTest(FabricTest):

    @autocleanup
    def doRunTest(self):
        req, _ = self.add_next_hashed_group_member("output_hashed", [("port_num", stringify(1, 2))])
        member_installed = req.updates[0].entity.action_profile_member
        mbr_id = member_installed.member_id

        grp_id = 1
        req, _ = self.add_next_hashed_group(grp_id, [mbr_id])
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        received_action_profile_group = self.read_next_hashed_group(grp_id)
        self.verify_p4runtime_entity(expected_action_profile_group, received_action_profile_group)

    def runTest(self):
        self.doRunTest()

@group("p4r-function")
class ActionProfileGroupModificationTest(FabricTest):

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
        self.doRunTest()
