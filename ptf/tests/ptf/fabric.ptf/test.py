# Copyright 2013-2018 Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

import difflib
import string
from unittest import skip

from base_test import autocleanup, tvsetup, tvskip
from fabric_test import *  # noqa
from p4.config.v1 import p4info_pb2
from ptf.testutils import group
from scapy.layers.inet import IP
from scapy.layers.ppp import PPPoED

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
        print("")
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                pktlen = 120
                tc_name = pkt_type + "_VLAN_" + vlan_conf + "_" + str(pktlen)
                print("Testing {} packet with VLAN {}..".format(pkt_type, vlan_conf))
                pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
                    pktlen=pktlen
                )
                self.doRunTest(tagged[0], tagged[1], pkt, tc_name=tc_name)


class FabricBridgingPriorityTest(BridgingPriorityTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        self.runBridgingPriorityTest()


class FabricDoubleTaggedBridgingTest(DoubleTaggedBridgingTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tc_name):
        self.runDoubleTaggedBridgingTest(pkt)

    def runTest(self):
        print("")
        for pkt_type in ["tcp", "udp", "icmp"]:
            pktlen = 120
            tc_name = pkt_type + "_DOUBLE_TAGGED" + "_" + str(pktlen)
            print("Testing double tagged {} packet ..".format(pkt_type))
            pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(pktlen=pktlen)
            self.doRunTest(pkt, tc_name=tc_name)


@skip("XConnect Currently Unsupported")
@group("xconnect")
class FabricDoubleVlanXConnectTest(DoubleVlanXConnectTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tc_name):
        self.runXConnectTest(pkt)

    def runTest(self):
        print("")
        for pkt_type in ["tcp", "udp", "icmp"]:
            pktlen = 120
            tc_name = pkt_type + "_" + str(pktlen)
            print("Testing {} packet...".format(pkt_type))
            pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(pktlen=pktlen)
            self.doRunTest(pkt, tc_name=tc_name)


@group("multicast")
class FabricArpBroadcastUntaggedTest(ArpBroadcastTest):
    @tvsetup
    @autocleanup
    def runTest(self):

        self.runArpBroadcastTest(
            tagged_ports=[], untagged_ports=[self.port1, self.port2, self.port3],
        )


@group("multicast")
class FabricArpBroadcastTaggedTest(ArpBroadcastTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port1, self.port2, self.port3], untagged_ports=[],
        )


@group("multicast")
class FabricArpBroadcastMixedTest(ArpBroadcastTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port2, self.port3], untagged_ports=[self.port1]
        )


@group("multicast")
class FabricIPv4MulticastTest(IPv4MulticastTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, in_vlan, out_vlan):
        pkt = testutils.simple_udp_packet(
            eth_dst="01:00:5e:00:00:01", ip_dst="224.0.0.1"
        )
        in_port = self.port1
        out_ports = [self.port2, self.port3]
        self.runIPv4MulticastTest(pkt, in_port, out_ports, in_vlan, out_vlan)

    def runTest(self):
        self.doRunTest(None, None)
        self.doRunTest(None, 10)
        self.doRunTest(10, None)
        self.doRunTest(10, 10)
        self.doRunTest(10, 11)


class FabricIPv4UnicastTest(IPv4UnicastTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, mac_dest, prefix_len, tagged1, tagged2, tc_name):
        self.runIPv4UnicastTest(
            pkt, mac_dest, prefix_len=prefix_len, tagged1=tagged1, tagged2=tagged2,
        )

    def runTest(self):
        self.runTestInternal(
            HOST2_IPV4, [PREFIX_DEFAULT_ROUTE, PREFIX_SUBNET, PREFIX_HOST]
        )

    def runTestInternal(self, ip_dst, prefix_list):
        print("")
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for prefix_len in prefix_list:
                    for pkt_len in [MIN_PKT_LEN, 1500]:
                        tc_name = (
                            pkt_type
                            + "_VLAN_"
                            + vlan_conf
                            + "_"
                            + ip_dst
                            + "/"
                            + str(prefix_len)
                            + "_"
                            + str(pkt_len)
                        )
                        print(
                            "Testing {} packet with VLAN {}, IP dest {}/{}, size {}...".format(
                                pkt_type, vlan_conf, ip_dst, prefix_len, pkt_len
                            )
                        )
                        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                            eth_src=HOST1_MAC,
                            eth_dst=SWITCH_MAC,
                            ip_src=HOST1_IPV4,
                            ip_dst=ip_dst,
                            pktlen=pkt_len,
                        )
                        self.doRunTest(
                            pkt,
                            HOST2_MAC,
                            prefix_len,
                            tagged[0],
                            tagged[1],
                            tc_name=tc_name,
                        )


class FabricIPv4UnicastDefaultRouteTest(FabricIPv4UnicastTest):
    def runTest(self):
        self.runTestInternal(DEFAULT_ROUTE_IPV4, [PREFIX_DEFAULT_ROUTE])


class FabricIPv4UnicastGtpPassthroughTest(IPv4UnicastTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        # Assert that GTP packets not meant to be processed by spgw.p4 are
        # forwarded using the outer IP+UDP headers.
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = (
            Ether(src=HOST1_MAC, dst=SWITCH_MAC)
            / IP(src=HOST3_IPV4, dst=HOST4_IPV4)
            / UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT)
            / GTPU(teid=0xEEFFC0F0)
            / IP(src=HOST1_IPV4, dst=HOST2_IPV4)
            / inner_udp
        )
        self.runIPv4UnicastTest(pkt, next_hop_mac=HOST2_MAC)


class FabricIPv4UnicastGroupTest(FabricTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(
            self.port1,
            SWITCH_MAC,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
        )
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan(self.port2, vlan_id, False)
        self.set_egress_vlan(self.port3, vlan_id, False)

        pkt_from1 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
        )
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC,
            eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
        )
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC,
            eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
        )

        self.send_packet(self.port1, pkt_from1)
        self.verify_any_packet_any_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
        )


class FabricIPv4UnicastGroupTestAllPortTcpSport(FabricTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        # In this test we check that packets are forwarded to all ports when we
        # change one of the 5-tuple header values. In this case tcp-source-port
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(
            self.port1,
            SWITCH_MAC,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
        )
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan(self.port2, vlan_id, False)
        self.set_egress_vlan(self.port3, vlan_id, False)
        # tcpsport_toport list is used to learn the tcp_source_port that
        # causes the packet to be forwarded for each port
        tcpsport_toport = [None, None]
        for i in range(50):
            test_tcp_sport = 1230 + i
            pkt_from1 = testutils.simple_tcp_packet(
                eth_src=HOST1_MAC,
                eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=HOST2_IPV4,
                ip_ttl=64,
                tcp_sport=test_tcp_sport,
            )
            exp_pkt_to2 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC,
                eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=HOST2_IPV4,
                ip_ttl=63,
                tcp_sport=test_tcp_sport,
            )
            exp_pkt_to3 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC,
                eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=HOST2_IPV4,
                ip_ttl=63,
                tcp_sport=test_tcp_sport,
            )
            self.send_packet(self.port1, pkt_from1)
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
            )
            tcpsport_toport[out_port_indx] = test_tcp_sport

        pkt_toport2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
            tcp_sport=tcpsport_toport[0],
        )
        pkt_toport3 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
            tcp_sport=tcpsport_toport[1],
        )
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC,
            eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
            tcp_sport=tcpsport_toport[0],
        )
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC,
            eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
            tcp_sport=tcpsport_toport[1],
        )
        self.send_packet(self.port1, pkt_toport2)
        self.send_packet(self.port1, pkt_toport3)
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the
        #     same 5-tuple fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
        )


class FabricIPv4UnicastGroupTestAllPortTcpDport(FabricTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        # In this test we check that packets are forwarded to all ports when we
        # change one of the 5-tuple header values. In this case tcp-dst-port
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(
            self.port1,
            SWITCH_MAC,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
        )
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan(self.port2, vlan_id, False)
        self.set_egress_vlan(self.port3, vlan_id, False)
        # tcpdport_toport list is used to learn the tcp_destination_port that
        # causes the packet to be forwarded for each port
        tcpdport_toport = [None, None]
        for i in range(50):
            test_tcp_dport = 1230 + 3 * i
            pkt_from1 = testutils.simple_tcp_packet(
                eth_src=HOST1_MAC,
                eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=HOST2_IPV4,
                ip_ttl=64,
                tcp_dport=test_tcp_dport,
            )
            exp_pkt_to2 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC,
                eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=HOST2_IPV4,
                ip_ttl=63,
                tcp_dport=test_tcp_dport,
            )
            exp_pkt_to3 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC,
                eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=HOST2_IPV4,
                ip_ttl=63,
                tcp_dport=test_tcp_dport,
            )
            self.send_packet(self.port1, pkt_from1)
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
            )
            tcpdport_toport[out_port_indx] = test_tcp_dport

        pkt_toport2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
            tcp_dport=tcpdport_toport[0],
        )
        pkt_toport3 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
            tcp_dport=tcpdport_toport[1],
        )
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC,
            eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
            tcp_dport=tcpdport_toport[0],
        )
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC,
            eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
            tcp_dport=tcpdport_toport[1],
        )
        self.send_packet(self.port1, pkt_toport2)
        self.send_packet(self.port1, pkt_toport3)
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the
        #     same 5-tuple fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
        )


class FabricIPv4UnicastGroupTestAllPortIpSrc(FabricTest):
    @tvsetup
    @autocleanup
    def IPv4UnicastGroupTestAllPortL4SrcIp(self, pkt_type):
        # In this test we check that packets are forwarded to all ports when we
        # change one of the 5-tuple header values and we have an ECMP-like
        # distribution.
        # In this case IP source for tcp and udp packets
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(
            self.port1,
            SWITCH_MAC,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
        )
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan(self.port2, vlan_id, False)
        self.set_egress_vlan(self.port3, vlan_id, False)
        # ipsource_toport list is used to learn the ip_src that causes the
        # packet to be forwarded for each port
        ipsource_toport = [None, None]
        for i in range(50):
            test_ipsource = "10.0.1." + str(i)
            pkt_from1 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC,
                eth_dst=SWITCH_MAC,
                ip_src=test_ipsource,
                ip_dst=HOST2_IPV4,
                ip_ttl=64,
            )
            exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC,
                eth_dst=HOST2_MAC,
                ip_src=test_ipsource,
                ip_dst=HOST2_IPV4,
                ip_ttl=63,
            )
            exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC,
                eth_dst=HOST3_MAC,
                ip_src=test_ipsource,
                ip_dst=HOST2_IPV4,
                ip_ttl=63,
            )
            self.send_packet(self.port1, pkt_from1)
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
            )
            ipsource_toport[out_port_indx] = test_ipsource

        pkt_toport2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=ipsource_toport[0],
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
        )
        pkt_toport3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=ipsource_toport[1],
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
        )
        exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC,
            eth_dst=HOST2_MAC,
            ip_src=ipsource_toport[0],
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
        )
        exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC,
            eth_dst=HOST3_MAC,
            ip_src=ipsource_toport[1],
            ip_dst=HOST2_IPV4,
            ip_ttl=63,
        )
        self.send_packet(self.port1, pkt_toport2)
        self.send_packet(self.port1, pkt_toport3)
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the
        #     same 5-tuple fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
        )

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4SrcIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4SrcIp("udp")
        self.IPv4UnicastGroupTestAllPortL4SrcIp("icmp")


class FabricIPv4UnicastGroupTestAllPortIpDst(FabricTest):
    @tvsetup
    @autocleanup
    def IPv4UnicastGroupTestAllPortL4DstIp(self, pkt_type):
        # In this test we check that packets are forwarded to all ports when we
        # change one of the 5-tuple header values and we have an ECMP-like
        # distribution.
        # In this case IP dest for tcp and udp packets
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(
            self.port1,
            SWITCH_MAC,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
        )
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = [
            (self.port2, SWITCH_MAC, HOST2_MAC),
            (self.port3, SWITCH_MAC, HOST3_MAC),
        ]
        self.add_next_routing_group(300, grp_id, mbrs)
        self.set_egress_vlan(self.port2, vlan_id, False)
        self.set_egress_vlan(self.port3, vlan_id, False)
        # ipdst_toport list is used to learn the ip_dst that causes the packet
        # to be forwarded for each port
        ipdst_toport = [None, None]
        for i in range(50):
            # If we increment test_ipdst by 1 on hardware, all 50 packets hash
            # to the same ECMP group member and the test fails. Changing the
            # increment to 3 makes this not happen. This seems extremely
            # unlikely and needs further testing to confirm. A similar
            # situation seems to be happening with
            # FabricIPv4UnicastGroupTestAllPortTcpDport
            test_ipdst = "10.0.2." + str(3 * i)
            pkt_from1 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC,
                eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=test_ipdst,
                ip_ttl=64,
            )
            exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC,
                eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=test_ipdst,
                ip_ttl=63,
            )
            exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC,
                eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=test_ipdst,
                ip_ttl=63,
            )
            self.send_packet(self.port1, pkt_from1)
            out_port_indx = self.verify_any_packet_any_port(
                [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
            )
            ipdst_toport[out_port_indx] = test_ipdst

        pkt_toport2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=ipdst_toport[0],
            ip_ttl=64,
        )
        pkt_toport3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=ipdst_toport[1],
            ip_ttl=64,
        )
        exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC,
            eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=ipdst_toport[0],
            ip_ttl=63,
        )
        exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC,
            eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=ipdst_toport[1],
            ip_ttl=63,
        )
        self.send_packet(self.port1, pkt_toport2)
        self.send_packet(self.port1, pkt_toport3)
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the
        #     same 5-tuple fields are always forwarded out of the same port
        self.verify_each_packet_on_each_port(
            [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3]
        )

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4DstIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4DstIp("udp")
        self.IPv4UnicastGroupTestAllPortL4DstIp("icmp")


class FabricIPv4MPLSTest(FabricTest):
    @tvsetup
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(
            self.port1,
            SWITCH_MAC,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
        )
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 400)
        mpls_label = 0xABA
        self.add_next_mpls_routing(400, self.port2, SWITCH_MAC, HOST2_MAC, mpls_label)
        self.set_egress_vlan(self.port2, vlan_id, False)

        pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC,
            eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4,
            ip_dst=HOST2_IPV4,
            ip_ttl=64,
        )
        exp_pkt_1to2 = testutils.simple_mpls_packet(
            eth_src=SWITCH_MAC,
            eth_dst=HOST2_MAC,
            mpls_tags=[{"label": mpls_label, "tc": 0, "s": 1, "ttl": DEFAULT_MPLS_TTL}],
            inner_frame=pkt_1to2[IP:],
        )

        self.send_packet(self.port1, pkt_1to2)
        self.verify_packets(exp_pkt_1to2, [self.port2])


class FabricIPv4MplsGroupTest(IPv4UnicastTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, mac_dest, tagged1, tc_name):
        self.runIPv4UnicastTest(
            pkt,
            mac_dest,
            prefix_len=24,
            tagged1=tagged1,
            tagged2=False,
            is_next_hop_spine=True,
        )

    def runTest(self):
        print("")
        for tagged1 in [True, False]:
            for pkt_type in ["tcp", "udp", "icmp"]:
                tc_name = pkt_type + "_tagged_" + str(tagged1)
                print("Testing {} packet with tagged={}...".format(pkt_type, tagged1))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC,
                    eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4,
                    ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN,
                )
                self.doRunTest(pkt, HOST2_MAC, tagged1, tc_name=tc_name)


class FabricMplsSegmentRoutingTest(MplsSegmentRoutingTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, mac_dest, next_hop_spine, tc_name):
        self.runMplsSegmentRoutingTest(pkt, mac_dest, next_hop_spine)

    def runTest(self):
        print("")
        for pkt_type in ["tcp", "udp", "icmp"]:
            for next_hop_spine in [True, False]:
                tc_name = pkt_type + "_next_hop_spine_" + str(next_hop_spine)
                print(
                    "Testing {} packet, next_hop_spine={}...".format(
                        pkt_type, next_hop_spine
                    )
                )
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC,
                    eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4,
                    ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN,
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
            self.send_packet(port, pkt)
            self.verify_packet_in(pkt, port)
        self.verify_no_other_packets()


@group("spgw")
class FabricSpgwDownlinkTest(SpgwSimpleTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged1, tagged2, is_next_hop_spine, tc_name):
        self.runDownlinkTest(
            pkt=pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

    def runTest(self):
        print("")
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    tc_name = (
                        "VLAN_"
                        + vlan_conf
                        + "_"
                        + pkt_type
                        + "_is_next_hop_spine_"
                        + str(is_next_hop_spine)
                    )
                    print(
                        "Testing VLAN={}, pkt={}, is_next_hop_spine={}...".format(
                            vlan_conf, pkt_type, is_next_hop_spine
                        )
                    )
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        eth_src=HOST1_MAC,
                        eth_dst=SWITCH_MAC,
                        ip_src=HOST1_IPV4,
                        ip_dst=UE1_IPV4,
                        pktlen=MIN_PKT_LEN,
                    )
                    self.doRunTest(
                        pkt, tagged[0], tagged[1], is_next_hop_spine, tc_name=tc_name,
                    )


@group("spgw")
class FabricSpgwReadWriteSymmetryTest(SpgwReadWriteSymmetryTest):
    @tvskip
    @autocleanup
    def runTest(self):
        self.runReadWriteSymmetryTest()


@group("spgw")
class FabricSpgwUplinkTest(SpgwSimpleTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged1, tagged2, is_next_hop_spine):
        self.runUplinkTest(
            ue_out_pkt=pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

    def runTest(self):
        print("")
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    print(
                        "Testing VLAN={}, pkt={}, is_next_hop_spine={}...".format(
                            vlan_conf, pkt_type, is_next_hop_spine
                        )
                    )
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        eth_src=HOST1_MAC,
                        eth_dst=SWITCH_MAC,
                        ip_src=HOST1_IPV4,
                        ip_dst=HOST2_IPV4,
                        pktlen=MIN_PKT_LEN,
                    )
                    self.doRunTest(pkt, tagged[0], tagged[1], is_next_hop_spine)


@group("spgw")
class FabricSpgwUplinkRecircTest(SpgwSimpleTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, allow, tagged1, tagged2, is_next_hop_spine):
        self.runUplinkRecircTest(
            ue_out_pkt=pkt,
            allow=allow,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

    def runTest(self):
        print("")
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for is_next_hop_spine in [False, True]:
                    for allow in [True, False]:
                        if is_next_hop_spine and (tagged[1] or not allow):
                            continue
                        print(
                            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, allow={}...".format(
                                vlan_conf, pkt_type, is_next_hop_spine, allow
                            )
                        )
                        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                            eth_src=HOST1_MAC,
                            eth_dst=SWITCH_MAC,
                            ip_src=UE1_IPV4,
                            ip_dst=UE2_IPV4,
                            pktlen=MIN_PKT_LEN,
                        )
                        self.doRunTest(
                            pkt, allow, tagged[0], tagged[1], is_next_hop_spine
                        )


@group("spgw")
class FabricSpgwDownlinkToDbufTest(SpgwSimpleTest):
    """Tests downlink packets arriving from the PDN being routed to
    the dbuf device for buffering.
    """

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged1, tagged2, is_next_hop_spine, tc_name):
        self.runDownlinkToDbufTest(
            pkt=pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

    def runTest(self):
        print("")
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    tc_name = (
                        "VLAN_"
                        + vlan_conf
                        + "_"
                        + pkt_type
                        + "_mpls_"
                        + str(is_next_hop_spine)
                    )
                    print(
                        "Testing VLAN={}, pkt={}, mpls={}...".format(
                            vlan_conf, pkt_type, is_next_hop_spine
                        )
                    )
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        eth_src=HOST1_MAC,
                        eth_dst=SWITCH_MAC,
                        ip_src=HOST1_IPV4,
                        ip_dst=UE1_IPV4,
                        pktlen=MIN_PKT_LEN,
                    )
                    self.doRunTest(
                        pkt, tagged[0], tagged[1], is_next_hop_spine, tc_name=tc_name,
                    )


@group("spgw")
class FabricSpgwDownlinkFromDbufTest(SpgwSimpleTest):
    """Tests downlink packets being drained from the dbuf buffering device
    back into the switch to be tunneled to the enodeb.
    """

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged1, tagged2, is_next_hop_spine, tc_name):
        self.runDownlinkFromDbufTest(
            pkt=pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

    def runTest(self):
        print("")
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    tc_name = (
                        "VLAN_"
                        + vlan_conf
                        + "_"
                        + pkt_type
                        + "_mpls_"
                        + str(is_next_hop_spine)
                    )
                    print(
                        "Testing VLAN={}, pkt={}, mpls={}...".format(
                            vlan_conf, pkt_type, is_next_hop_spine
                        )
                    )
                    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                        eth_src=DBUF_MAC,
                        eth_dst=SWITCH_MAC,
                        ip_src=HOST1_IPV4,
                        ip_dst=UE1_IPV4,
                        pktlen=MIN_PKT_LEN,
                    )
                    self.doRunTest(
                        pkt, tagged[0], tagged[1], is_next_hop_spine, tc_name=tc_name,
                    )


@group("int")
@group("spgw")
class FabricSpgwUplinkIntTest(SpgwIntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self,
        vlan_conf,
        tagged,
        pkt_type,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, is_device_spine={}, send_report_to_spine={}...".format(
                vlan_conf,
                pkt_type,
                is_next_hop_spine,
                is_device_spine,
                send_report_to_spine,
            )
        )
        # Change the IP destination to ensure we are using differnt
        # flow for diffrent test cases since the flow report filter
        # might disable the report.
        # TODO: Remove this part when we are able to reset the register
        # via P4Runtime.
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
            ip_dst=self.get_single_use_ip()
        )
        self.runSpgwUplinkIntTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            is_device_spine=is_device_spine,
            send_report_to_spine=send_report_to_spine,
        )

    def runTest(self):
        print("")
        for is_device_spine in [False, True]:
            for vlan_conf, tagged in vlan_confs.items():
                if is_device_spine and (tagged[0] or tagged[1]):
                    continue
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    for send_report_to_spine in [False, True]:
                        if send_report_to_spine and tagged[1]:
                            continue
                        for pkt_type in ["udp", "tcp", "icmp"]:
                            self.doRunTest(
                                vlan_conf,
                                tagged,
                                pkt_type,
                                is_next_hop_spine,
                                is_device_spine,
                                send_report_to_spine,
                            )


@group("int")
@group("spgw")
class FabricSpgwDownlinkIntTest(SpgwIntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self,
        vlan_conf,
        tagged,
        pkt_type,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, is_device_spine={}, send_report_to_spine={}...".format(
                vlan_conf,
                pkt_type,
                is_next_hop_spine,
                is_device_spine,
                send_report_to_spine,
            )
        )
        # Change the IP destination to ensure we are using differnt
        # flow for diffrent test cases since the flow report filter
        # might disable the report.
        # TODO: Remove this part when we are able to reset the register
        # via P4Runtime.
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
            ip_dst=self.get_single_use_ip()
        )
        self.runSpgwDownlinkIntTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            is_device_spine=is_device_spine,
            send_report_to_spine=send_report_to_spine,
        )

    def runTest(self):
        print("")
        for is_device_spine in [False, True]:
            for vlan_conf, tagged in vlan_confs.items():
                if is_device_spine and (tagged[0] or tagged[1]):
                    continue
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    for send_report_to_spine in [False, True]:
                        if send_report_to_spine and tagged[1]:
                            continue
                        for pkt_type in ["udp", "tcp", "icmp"]:
                            self.doRunTest(
                                vlan_conf,
                                tagged,
                                pkt_type,
                                is_next_hop_spine,
                                is_device_spine,
                                send_report_to_spine,
                            )


# This test will assume the packet hits spgw interface and miss the uplink PDR table or
# the FAR table
@group("int")
@group("spgw")
class FabricSpgwIntUplinkDropTest(SpgwIntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self,
        vlan_conf,
        tagged,
        pkt_type,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
        drop_reason,
    ):
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, is_device_spine={}, send_report_to_spine={}, drop_reason={}...".format(
                vlan_conf,
                pkt_type,
                is_next_hop_spine,
                is_device_spine,
                send_report_to_spine,
                drop_reason,
            )
        )
        # Change the IP destination to ensure we are using differnt
        # flow for diffrent test cases since the flow report filter
        # might disable the report.
        # TODO: Remove this part when we are able to reset the register
        # via P4Runtime.
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
            ip_dst=self.get_single_use_ip()
        )
        self.runUplinkIntDropTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            ig_port=self.port1,
            eg_port=self.port2,
            expect_int_report=True,
            is_device_spine=is_device_spine,
            send_report_to_spine=send_report_to_spine,
            drop_reason=drop_reason,
        )

    def runTest(self):
        print("")
        for drop_reason in [INT_DROP_REASON_UPLINK_PDR_MISS, INT_DROP_REASON_FAR_MISS]:
            for is_device_spine in [False, True]:
                for vlan_conf, tagged in vlan_confs.items():
                    if is_device_spine and (tagged[0] or tagged[1]):
                        continue
                    for is_next_hop_spine in [False, True]:
                        if is_next_hop_spine and tagged[1]:
                            continue
                        for send_report_to_spine in [False, True]:
                            if send_report_to_spine and tagged[1]:
                                continue
                            for pkt_type in ["udp", "tcp", "icmp"]:
                                self.doRunTest(
                                    vlan_conf,
                                    tagged,
                                    pkt_type,
                                    is_next_hop_spine,
                                    is_device_spine,
                                    send_report_to_spine,
                                    drop_reason,
                                )


# This test will assume the packet hits spgw interface and miss the downlink PDR table or
# the FAR table
@group("int")
@group("spgw")
class FabricSpgwIntDownlinkDropTest(SpgwIntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self,
        vlan_conf,
        tagged,
        pkt_type,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
        drop_reason,
    ):
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, is_device_spine={}, send_report_to_spine={}, drop_reason={}...".format(
                vlan_conf,
                pkt_type,
                is_next_hop_spine,
                is_device_spine,
                send_report_to_spine,
                drop_reason,
            )
        )
        # Change the IP destination to ensure we are using differnt
        # flow for diffrent test cases since the flow report filter
        # might disable the report.
        # TODO: Remove this part when we are able to reset the register
        # via P4Runtime.
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
            ip_dst=self.get_single_use_ip()
        )
        self.runDownlinkIntDropTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            ig_port=self.port1,
            eg_port=self.port2,
            expect_int_report=True,
            is_device_spine=is_device_spine,
            send_report_to_spine=send_report_to_spine,
            drop_reason=drop_reason,
        )

    def runTest(self):
        print("")
        for drop_reason in [
            INT_DROP_REASON_DOWNLINK_PDR_MISS,
            INT_DROP_REASON_FAR_MISS,
        ]:
            for is_device_spine in [False, True]:
                for vlan_conf, tagged in vlan_confs.items():
                    if is_device_spine and (tagged[0] or tagged[1]):
                        continue
                    for is_next_hop_spine in [False, True]:
                        if is_next_hop_spine and tagged[1]:
                            continue
                        for send_report_to_spine in [False, True]:
                            if send_report_to_spine and tagged[1]:
                                continue
                            for pkt_type in ["udp", "tcp", "icmp"]:
                                self.doRunTest(
                                    vlan_conf,
                                    tagged,
                                    pkt_type,
                                    is_next_hop_spine,
                                    is_device_spine,
                                    send_report_to_spine,
                                    drop_reason,
                                )


@group("int")
class FabricIntLocalReportTest(IntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self,
        vlan_conf,
        tagged,
        pkt_type,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, "
            "is_device_spine={}, send_report_to_spine={}...".format(
                vlan_conf,
                pkt_type,
                is_next_hop_spine,
                is_device_spine,
                send_report_to_spine,
            )
        )
        # Change the IP destination to ensure we are using differnt
        # flow for diffrent test cases since the flow report filter
        # might disable the report.
        # TODO: Remove this part when we are able to reset the register
        # via P4Runtime.
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
            ip_dst=self.get_single_use_ip()
        )
        self.runIntTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            ig_port=self.port1,
            eg_port=self.port2,
            expect_int_report=True,
            is_device_spine=is_device_spine,
            send_report_to_spine=send_report_to_spine,
        )

    def runTest(self):
        print("")
        for is_device_spine in [False, True]:
            for vlan_conf, tagged in vlan_confs.items():
                if is_device_spine and (tagged[0] or tagged[1]):
                    continue
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    for send_report_to_spine in [False, True]:
                        if send_report_to_spine and tagged[1]:
                            continue
                        for pkt_type in ["udp", "tcp", "icmp"]:
                            self.doRunTest(
                                vlan_conf,
                                tagged,
                                pkt_type,
                                is_next_hop_spine,
                                is_device_spine,
                                send_report_to_spine,
                            )


@group("int")
class FabricIntIngressDropReportTest(IntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self,
        vlan_conf,
        tagged,
        pkt_type,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
        drop_reason,
    ):
        self.set_up_flow_report_filter_config(
            hop_latency_mask=0xF0000000, timestamp_mask=0xFFFFFFFF
        )
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, "
            "is_device_spine={}, send_report_to_spine={}, drop_reason={}...".format(
                vlan_conf,
                pkt_type,
                is_next_hop_spine,
                is_device_spine,
                send_report_to_spine,
                drop_reason,
            )
        )
        # Change the IP destination to ensure we are using differnt
        # flow for diffrent test cases since the flow report filter
        # might disable the report.
        # TODO: Remove this part when we are able to reset the register
        # via P4Runtime.
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
            ip_dst=self.get_single_use_ip()
        )
        self.runIngressIntDropTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            ig_port=self.port1,
            eg_port=0,  # packet will be dropped by the pipeline
            expect_int_report=True,
            is_device_spine=is_device_spine,
            send_report_to_spine=send_report_to_spine,
            drop_reason=drop_reason,
        )

    def runTest(self):
        print("")
        # FIXME: Add INT_DROP_REASON_ROUTING_V4_MISS. Currently, there is an unknown bug
        #        which cause unexpected table(drop_report) miss.
        for drop_reason in [INT_DROP_REASON_ACL_DENY]:
            for is_device_spine in [False, True]:
                for vlan_conf, tagged in vlan_confs.items():
                    if is_device_spine and (tagged[0] or tagged[1]):
                        continue
                    for is_next_hop_spine in [False, True]:
                        if is_next_hop_spine and tagged[1]:
                            continue
                        for send_report_to_spine in [False, True]:
                            if send_report_to_spine and tagged[1]:
                                continue
                            for pkt_type in ["udp", "tcp", "icmp"]:
                                self.doRunTest(
                                    vlan_conf,
                                    tagged,
                                    pkt_type,
                                    is_next_hop_spine,
                                    is_device_spine,
                                    send_report_to_spine,
                                    drop_reason,
                                )


@group("int")
class FabricIntEgressDropReportTest(IntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self,
        vlan_conf,
        tagged,
        pkt_type,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        self.set_up_flow_report_filter_config(
            hop_latency_mask=0xF0000000, timestamp_mask=0xFFFFFFFF
        )
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}, "
            "is_device_spine={}, send_report_to_spine={}...".format(
                vlan_conf,
                pkt_type,
                is_next_hop_spine,
                is_device_spine,
                send_report_to_spine,
            )
        )
        # Change the IP destination to ensure we are using differnt
        # flow for diffrent test cases since the flow report filter
        # might disable the report.
        # TODO: Remove this part when we are able to reset the register
        # via P4Runtime.
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
            ip_dst=self.get_single_use_ip()
        )
        self.runEgressIntDropTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            ig_port=self.port1,
            eg_port=self.port2,
            expect_int_report=True,
            is_device_spine=is_device_spine,
            send_report_to_spine=send_report_to_spine,
            drop_reason=INT_DROP_REASON_EGRESS_NEXT_MISS,
        )

    def runTest(self):
        print("")
        for is_device_spine in [False, True]:
            for vlan_conf, tagged in vlan_confs.items():
                if is_device_spine and (tagged[0] or tagged[1]):
                    continue
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    for send_report_to_spine in [False, True]:
                        if send_report_to_spine and tagged[1]:
                            continue
                        for pkt_type in ["udp", "tcp", "icmp"]:
                            self.doRunTest(
                                vlan_conf,
                                tagged,
                                pkt_type,
                                is_next_hop_spine,
                                is_device_spine,
                                send_report_to_spine,
                            )


@group("int")
class FabricFlowReportFilterNoChangeTest(IntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self, vlan_conf, tagged, pkt_type, is_next_hop_spine, expect_int_report, ip_dst,
    ):
        self.set_up_flow_report_filter_config(
            hop_latency_mask=0xF0000000, timestamp_mask=0
        )
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}...".format(
                vlan_conf, pkt_type, is_next_hop_spine
            )
        )
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(ip_dst=ip_dst)
        self.runIntTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            ig_port=self.port1,
            eg_port=self.port2,
            expect_int_report=expect_int_report,
            is_device_spine=False,
            send_report_to_spine=False,
        )

    def runTest(self):
        print("")
        for pkt_type in ["udp", "tcp", "icmp"]:
            expect_int_report = True
            # Change the IP destination to ensure we are using differnt
            # flow for diffrent test cases since the flow report filter
            # might disable the report.
            # TODO: Remove this part when we are able to reset the register
            # via P4Runtime.
            ip_dst = self.get_single_use_ip()
            for vlan_conf, tagged in vlan_confs.items():
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    self.doRunTest(
                        vlan_conf,
                        tagged,
                        pkt_type,
                        is_next_hop_spine,
                        expect_int_report,
                        ip_dst,
                    )

                    # We should expect not receving any report after the first
                    # report since packet uses 5-tuple as flow ID.
                    expect_int_report = False


@group("int")
class FabricFlowReportFilterChangeTest(IntTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, ig_port, eg_port, expect_int_report, ip_src, ip_dst):
        self.set_up_flow_report_filter_config(
            hop_latency_mask=0xF0000000, timestamp_mask=0
        )
        print(
            "Testing ig_port={}, eg_port={}, expect_int_report={}...".format(
                ig_port, eg_port, expect_int_report
            )
        )
        pkt = testutils.simple_tcp_packet()
        pkt[IP].src = ip_src
        pkt[IP].dst = ip_dst
        self.runIntTest(
            pkt=pkt,
            tagged1=None,
            tagged2=None,
            is_next_hop_spine=False,
            ig_port=ig_port,
            eg_port=eg_port,
            expect_int_report=expect_int_report,
            is_device_spine=False,
            send_report_to_spine=False,
        )

    def runTest(self):
        print("")
        # Test with ingress port changed.
        ingress_port_test_profiles = [
            (self.port1, self.port2, True),  # ig port, eg port, receive report
            (self.port1, self.port2, False),
            (self.port4, self.port2, True),
        ]
        ip_src = self.get_single_use_ip()
        ip_dst = self.get_single_use_ip()
        for ig_port, eg_port, expect_int_report in ingress_port_test_profiles:
            self.doRunTest(
                ig_port=ig_port,
                eg_port=eg_port,
                ip_src=ip_src,
                ip_dst=ip_dst,
                expect_int_report=expect_int_report,
            )
        # Test with egress port changed.
        egress_port_test_profiles = [
            (self.port1, self.port2, True),  # ig port, eg port, receive report
            (self.port1, self.port2, False),
            (self.port1, self.port4, True),
        ]
        ip_src = self.get_single_use_ip()
        ip_dst = self.get_single_use_ip()
        for ig_port, eg_port, expect_int_report in egress_port_test_profiles:
            self.doRunTest(
                ig_port=ig_port,
                eg_port=eg_port,
                ip_src=ip_src,
                ip_dst=ip_dst,
                expect_int_report=expect_int_report,
            )


@group("int")
class FabricDropReportFilterTest(IntTest):
    @tvsetup
    @autocleanup
    def doRunTest(
        self, vlan_conf, tagged, pkt_type, is_next_hop_spine, expect_int_report, ip_dst,
    ):
        self.set_up_flow_report_filter_config(
            hop_latency_mask=0xF0000000, timestamp_mask=0
        )
        print(
            "Testing VLAN={}, pkt={}, is_next_hop_spine={}...".format(
                vlan_conf, pkt_type, is_next_hop_spine
            )
        )
        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(ip_dst=ip_dst)
        self.runIngressIntDropTest(
            pkt=pkt,
            tagged1=tagged[0],
            tagged2=tagged[1],
            is_next_hop_spine=is_next_hop_spine,
            ig_port=self.port1,
            eg_port=0,  # packet will be dropped by the pipeline
            expect_int_report=expect_int_report,
            is_device_spine=False,
            send_report_to_spine=False,
            drop_reason=INT_DROP_REASON_ACL_DENY,
        )

    def runTest(self):
        print("")
        for pkt_type in ["udp", "tcp", "icmp"]:
            expect_int_report = True
            # Change the IP destination to ensure we are using differnt
            # flow for diffrent test cases since the flow report filter
            # might disable the report.
            # TODO: Remove this part when we are able to reset the register
            # via P4Runtime.
            ip_dst = self.get_single_use_ip()
            for vlan_conf, tagged in vlan_confs.items():
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and tagged[1]:
                        continue
                    self.doRunTest(
                        vlan_conf,
                        tagged,
                        pkt_type,
                        is_next_hop_spine,
                        expect_int_report,
                        ip_dst,
                    )

                    # We should expect not receving any report after the first
                    # report since packet uses 5-tuple as flow ID.
                    expect_int_report = False


@group("bng")
class FabricPppoeUpstreamTest(PppoeTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, tagged2, is_next_hop_spine, line_enabled):
        self.runUpstreamV4Test(pkt, tagged2, is_next_hop_spine, line_enabled)

    def runTest(self):
        print("")
        for line_enabled in [True, False]:
            for out_tagged in [False, True]:
                for is_next_hop_spine in [False, True]:
                    if is_next_hop_spine and out_tagged:
                        continue
                    for pkt_type in ["tcp", "udp", "icmp"]:
                        print(
                            "Testing {} packet, line_enabled={}, out_tagged={}, is_next_hop_spine={} ...".format(
                                pkt_type, line_enabled, out_tagged, is_next_hop_spine
                            )
                        )
                        pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
                            pktlen=120
                        )
                        self.doRunTest(pkt, out_tagged, is_next_hop_spine, line_enabled)


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
            "PADI": Ether(src=HOST1_MAC, dst=BROADCAST_MAC)
            / PPPoED(version=1, type=1, code=PPPOED_CODE_PADI)
            / "dummy pppoed payload",
            "PADR": Ether(src=HOST1_MAC, dst=SWITCH_MAC)
            / PPPoED(version=1, type=1, code=PPPOED_CODE_PADR)
            / "dummy pppoed payload",
        }

        print("")
        for line_mapped in [True, False]:
            for pkt_type, pkt in pkts.items():
                print(
                    "Testing {} packet, line_mapped={}...".format(pkt_type, line_mapped)
                )
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
            "PADO": Ether(src=SWITCH_MAC, dst=HOST1_MAC)
            / PPPoED(version=1, type=1, code=PPPOED_CODE_PADO)
            / "dummy pppoed payload",
            "PADS": Ether(src=SWITCH_MAC, dst=HOST1_MAC)
            / PPPoED(version=1, type=1, code=PPPOED_CODE_PADS)
            / "dummy pppoed payload",
        }

        print("")
        for pkt_type, pkt in pkts.items():
            print("Testing {} packet...".format(pkt_type))
            self.doRunTest(pkt)


@group("bng")
class FabricPppoeDownstreamTest(PppoeTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, in_tagged, line_enabled):
        self.runDownstreamV4Test(pkt, in_tagged, line_enabled)

    def runTest(self):
        print("")
        for line_enabled in [True, False]:
            for in_tagged in [False, True]:
                for pkt_type in ["tcp", "udp", "icmp"]:
                    print(
                        "Testing {} packet, line_enabled={}, "
                        "in_tagged={}...".format(pkt_type, line_enabled, in_tagged)
                    )
                    pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
                        pktlen=120
                    )
                    self.doRunTest(pkt, in_tagged, line_enabled)


@group("dth")
class FabricDoubleTaggedHostUpstream(DoubleVlanTerminationTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, out_tagged, is_next_hop_spine):
        self.runPopAndRouteTest(
            pkt,
            next_hop_mac=HOST2_MAC,
            vlan_id=VLAN_ID_1,
            inner_vlan_id=VLAN_ID_2,
            out_tagged=out_tagged,
            is_next_hop_spine=is_next_hop_spine,
        )

    def runTest(self):
        print("")
        for out_tagged in [True, False]:
            for is_next_hop_spine in [True, False]:
                if is_next_hop_spine and out_tagged:
                    continue
                for pkt_type in ["tcp", "udp", "icmp"]:
                    print(
                        "Testing {} packet, out_tagged={}...".format(
                            pkt_type, out_tagged
                        )
                    )
                    pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
                        pktlen=120
                    )
                    self.doRunTest(pkt, out_tagged, is_next_hop_spine)


@group("dth")
class FabricDoubleTaggedHostDownstream(DoubleVlanTerminationTest):
    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, in_tagged):
        self.runRouteAndPushTest(
            pkt,
            next_hop_mac=HOST2_MAC,
            next_vlan_id=VLAN_ID_1,
            next_inner_vlan_id=VLAN_ID_2,
            in_tagged=in_tagged,
        )

    def runTest(self):
        print("")
        for in_tagged in [True, False]:
            for pkt_type in ["tcp", "udp", "icmp"]:
                print("Testing {} packet, in_tagged={}...".format(pkt_type, in_tagged))
                pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
                    pktlen=120
                )
                self.doRunTest(pkt, in_tagged)


@group("p4rt")
class TableEntryReadWriteTest(FabricTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_bridging_entry(1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 1)
        expected_bridging_entry = req.updates[0].entity.table_entry
        received_bridging_entry = self.read_bridging_entry(
            1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"
        )
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
        req, _ = self.add_next_hashed_group_member(
            "output_hashed", [("port_num", stringify(1, 2))]
        )
        expected_action_profile_member = req.updates[0].entity.action_profile_member
        mbr_id = expected_action_profile_member.member_id
        received_action_profile_member = self.read_next_hashed_group_member(mbr_id)
        self.verify_p4runtime_entity(
            expected_action_profile_member, received_action_profile_member
        )

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class ActionProfileGroupReadWriteTest(FabricTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_next_hashed_group_member(
            "output_hashed", [("port_num", stringify(1, 2))]
        )
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
            req, _ = self.add_next_hashed_group_member(
                "output_hashed", [("port_num", stringify(port_num, 2))]
            )
            member_installed = req.updates[0].entity.action_profile_member
            mbr_ids.append(member_installed.member_id)

        # Insert group with member-1 and member-2
        grp_id = 1
        req, _ = self.add_next_hashed_group(grp_id, mbr_ids[:2])
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        received_action_profile_group = self.read_next_hashed_group(grp_id)
        self.verify_p4runtime_entity(
            expected_action_profile_group, received_action_profile_group
        )

        # Modify group with member-2 and member-3
        req, _ = self.modify_next_hashed_group(grp_id, mbr_ids[1:], grp_size=2)
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        received_action_profile_group = self.read_next_hashed_group(grp_id)
        self.verify_p4runtime_entity(
            expected_action_profile_group, received_action_profile_group
        )

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
        expected_mc_entry = req.updates[
            0
        ].entity.packet_replication_engine_entry.multicast_group_entry
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
        # (instance, port)
        replicas = [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3)]
        self.add_mcast_group(grp_id, replicas)

        # Modify the group with egress port 2~4 (instance 2 and 3)
        # (instance, port)
        replicas = [(2, 2), (2, 3), (2, 4), (3, 2), (3, 3), (3, 4)]
        req, _ = self.modify_mcast_group(grp_id, replicas)
        expected_mc_entry = req.updates[
            0
        ].entity.packet_replication_engine_entry.multicast_group_entry
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
        table_entries = [
            req.updates[0].entity.table_entry
            for req in self.reqs
            if req.updates[0].entity.HasField("table_entry")
        ]
        ingress_port_vlan_tid = self.get_table_id("ingress_port_vlan")
        table_entries = [
            te for te in table_entries if te.table_id == ingress_port_vlan_tid
        ]

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
        except Exception:
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
            pkt, next_hop_mac=next_hop_mac, prefix_len=24, no_send=True
        )
        exp_pkt_1 = (
            Ether(type=ETH_TYPE_CPU_LOOPBACK_INGRESS, src=ZERO_MAC, dst=ZERO_MAC) / pkt
        )
        routed_pkt = pkt_decrement_ttl(pkt_route(pkt, next_hop_mac))
        exp_pkt_2 = (
            Ether(type=ETH_TYPE_CPU_LOOPBACK_EGRESS, src=ZERO_MAC, dst=ZERO_MAC)
            / routed_pkt
        )
        self.send_packet_out(
            self.build_packet_out(
                pkt, self.port1, cpu_loopback_mode=CPU_LOOPBACK_MODE_INGRESS
            )
        )
        self.verify_packet(exp_pkt_1, self.port1)
        self.send_packet(self.port1, exp_pkt_1)
        self.verify_packet(exp_pkt_2, self.port2)
        self.send_packet(self.port2, exp_pkt_2)
        self.verify_packet_in(routed_pkt, self.port2)
        self.verify_no_other_packets()

    def runTest(self):
        print("")
        for pkt_type in ["tcp", "udp", "icmp"]:
            print("Testing {} packet...".format(pkt_type))
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC,
                eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4,
                ip_dst=HOST2_IPV4,
                pktlen=MIN_PKT_LEN,
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
        exp_pkt_1 = (
            Ether(type=ETH_TYPE_CPU_LOOPBACK_INGRESS, src=ZERO_MAC, dst=ZERO_MAC) / pkt
        )
        for port in [self.port1, self.port2]:
            if tagged:
                self.set_ingress_port_vlan(port, True, VLAN_ID_1, VLAN_ID_1)
            else:
                self.set_ingress_port_vlan(port, False, 0, VLAN_ID_1)
            self.send_packet_out(
                self.build_packet_out(
                    pkt, port, cpu_loopback_mode=CPU_LOOPBACK_MODE_INGRESS
                )
            )
            self.verify_packet(exp_pkt_1, port)
            self.send_packet(port, exp_pkt_1)
            self.verify_packet_in(pkt, port)
        self.verify_no_other_packets()

    def runTest(self):
        print("")
        for pkt_type in ["tcp", "udp", "icmp", "arp"]:
            for tagged in [True, False]:
                print("Testing {} packet, tagged={}...".format(pkt_type, tagged))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, tagged)


# FIXME: remove when we start running TVs on hardware
class FabricPacketOutLoopbackModeTest(FabricTest):
    """Emulates TV loopback mode for packet-out tests"""

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt):
        exp_pkt_1 = (
            Ether(type=ETH_TYPE_CPU_LOOPBACK_EGRESS, src=ZERO_MAC, dst=ZERO_MAC) / pkt
        )
        for port in [self.port1, self.port2]:
            self.send_packet_out(
                self.build_packet_out(
                    pkt, port, cpu_loopback_mode=CPU_LOOPBACK_MODE_DIRECT
                )
            )
            self.verify_packet(exp_pkt_1, port)
            self.send_packet(port, exp_pkt_1)
            self.verify_packet_in(pkt, port)
        self.verify_no_other_packets()

    def runTest(self):
        print("")
        for pkt_type in ["tcp", "udp", "icmp", "arp"]:
            print("Testing {} packet...".format(pkt_type))
            pkt = getattr(testutils, "simple_{}_packet".format(pkt_type))(
                pktlen=MIN_PKT_LEN
            )
            self.doRunTest(pkt)


class FabricOptimizedFieldDetectorTest(FabricTest):
    """Finds action paramters or header fields that were optimized out by the
    compiler"""

    # Returns a byte string encoded value fitting into bitwidth.
    def generateBytestring(self, bitwidth):
        return stringify(1, (bitwidth + 7) // 8)

    # Since the test uses the same match key for tables with multiple actions,
    # each table entry has to be removed before testing the next.
    @autocleanup
    def insert_table_entry(
        self, table_name, match_keys, action_name, action_params, priority
    ):
        req, _ = self.send_request_add_entry_to_action(
            table_name, match_keys, action_name, action_params, priority
        )
        # Make a deep copy of the requests, because autocleanup will modify the
        # originals.
        write_entry = p4runtime_pb2.TableEntry()
        write_entry.CopyFrom(req.updates[0].entity.table_entry)
        resp = self.read_table_entry(table_name, match_keys, priority)
        if resp is None:
            self.fail(
                "Failed to read an entry that was just written! "
                "Table was {}, action was {}".format(table_name, action_name)
            )
        read_entry = p4runtime_pb2.TableEntry()
        read_entry.CopyFrom(resp)
        return write_entry, read_entry

    @autocleanup
    def insert_action_profile_member(
        self, action_profile_name, member_id, action_name, action_params
    ):
        req, _ = self.send_request_add_member(
            action_profile_name, member_id, action_name, action_params
        )
        # Make a deep copy of the requests, because autocleanup will modify the
        # originals.
        write_entry = p4runtime_pb2.ActionProfileMember()
        write_entry.CopyFrom(req.updates[0].entity.action_profile_member)
        read_entry = p4runtime_pb2.ActionProfileMember()
        read_entry.CopyFrom(
            self.read_action_profile_member(action_profile_name, member_id)
        )
        return write_entry, read_entry

    def handleTable(self, table):
        table_name = self.get_obj_name_from_id(table.preamble.id)
        priority = 0
        for action_ref in table.action_refs:
            # Build match
            match_keys = []
            for match in table.match_fields:
                if match.match_type == p4info_pb2.MatchField.MatchType.EXACT:
                    match_value = self.generateBytestring(match.bitwidth)
                    match_keys.append(self.Exact(match.name, match_value))
                elif match.match_type == p4info_pb2.MatchField.MatchType.LPM:
                    match_value = self.generateBytestring(match.bitwidth)
                    match_len = match.bitwidth
                    match_keys.append(self.Lpm(match.name, match_value, match_len))
                elif match.match_type == p4info_pb2.MatchField.MatchType.TERNARY:
                    match_value = self.generateBytestring(match.bitwidth)
                    match_mask = match_value
                    match_keys.append(self.Ternary(match.name, match_value, match_mask))
                    priority = 1
                elif match.match_type == p4info_pb2.MatchField.MatchType.RANGE:
                    match_low = self.generateBytestring(match.bitwidth)
                    match_high = match_low
                    match_keys.append(self.Range(match.name, match_low, match_high))
                    priority = 1
                else:
                    print(
                        "Skipping table %s because it has a unsupported match field %s of type %s"
                        % (table_name, match.name, match.match_type)
                    )
                    return
            # Build action
            action_name = self.get_obj_name_from_id(action_ref.id)
            action = self.get_obj("actions", action_name)
            action_params = []
            if action_ref.scope == p4info_pb2.ActionRef.Scope.DEFAULT_ONLY:
                # Modify as default action
                match_keys = []
                priority = 0
            if table.const_default_action_id > 0 and len(match_keys) == 0:
                # Don't try to modify a const default action
                print(
                    'Skipping action "%s" of table "%s" because the default action is const'
                    % (action_name, table_name)
                )
                continue
            for param in action.params:
                param_value = self.generateBytestring(param.bitwidth)
                action_params.append((param.name, param_value))

            write_entry = None
            read_entry = None
            if table.implementation_id > 0:
                action_profile_name = self.get_obj_name_from_id(table.implementation_id)
                action_profile = self.get_obj("action_profiles", action_profile_name)
                member_id = 1
                write_entry, read_entry = self.insert_action_profile_member(
                    action_profile_name, member_id, action_name, action_params
                )
                # TODO: Test table entries to members?
            else:
                write_entry, read_entry = self.insert_table_entry(
                    table_name, match_keys, action_name, action_params, priority
                )
            # Check for differences between expected and actual state.
            if write_entry != read_entry:
                write_entry_s = str.split(str(write_entry), "\n")
                read_entry_s = str.split(str(read_entry), "\n")
                diff = ""
                for line in difflib.unified_diff(
                    write_entry_s,
                    read_entry_s,
                    fromfile="Wrote",
                    tofile="Read back",
                    n=5,
                    lineterm="",
                ):
                    diff = diff + line + "\n"
                print(
                    'Found parameter that has been optimized out in action "%s" of table "%s":'
                    % (action_name, table_name)
                )
                print(diff)
                self.fail("Read does not match previous write!")

    @autocleanup
    def doRunTest(self):
        for table in getattr(self.p4info, "tables"):
            self.handleTable(table)

    def runTest(self):
        if self.generate_tv:
            return
        print("")
        self.doRunTest()
