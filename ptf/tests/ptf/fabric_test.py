# Copyright 2013-2018 Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

import socket
import struct
import time

import xnt
from base_test import P4RuntimeTest, ipv4_to_binary, mac_to_binary, stringify, tvcreate
from p4.v1 import p4runtime_pb2
from ptf import testutils
from ptf.mask import Mask
from scapy.contrib.mpls import MPLS
from scapy.fields import BitField, ByteField, IntField, ShortField
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.ppp import PPP, PPPoE
from scapy.packet import Packet, bind_layers

DEFAULT_PRIORITY = 10

FORWARDING_TYPE_BRIDGING = 0
FORWARDING_TYPE_MPLS = 1
FORWARDING_TYPE_UNICAST_IPV4 = 2
FORWARDING_TYPE_IPV4_MULTICAST = 3
FORWARDING_TYPE_IPV6_UNICAST = 4
FORWARDING_TYPE_IPV6_MULTICAST = 5
FORWARDING_TYPE_UNKNOWN = 7

CPU_CLONE_SESSION_ID = 511

DEFAULT_MPLS_TTL = 64
MIN_PKT_LEN = 80

UDP_GTP_PORT = 2152
DEFAULT_GTP_TUNNEL_SPORT = 1234  # arbitrary, but different from 2152

ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_QINQ = 0x88A8
ETH_TYPE_PPPOE = 0x8864
ETH_TYPE_MPLS_UNICAST = 0x8847

ETH_TYPE_PACKET_OUT = 0xBF01
ETH_TYPE_CPU_LOOPBACK_INGRESS = 0xBF02
ETH_TYPE_CPU_LOOPBACK_EGRESS = 0xBF03

CPU_LOOPBACK_MODE_DISABLED = 0
CPU_LOOPBACK_MODE_DIRECT = 1
CPU_LOOPBACK_MODE_INGRESS = 2

# In case the "correct" version of scapy (from p4lang) is not installed, we
# provide the INT header formats in xnt.py
# import scapy.main
# scapy.main.load_contrib("xnt")
# INT_META_HDR = scapy.contrib.xnt.INT_META_HDR
# INT_L45_HEAD = scapy.contrib.xnt.INT_L45_HEAD
# INT_L45_TAIL = scapy.contrib.xnt.INT_L45_TAIL
INT_META_HDR = xnt.INT_META_HDR
INT_L45_HEAD = xnt.INT_L45_HEAD
INT_L45_TAIL = xnt.INT_L45_TAIL
INT_L45_REPORT_FIXED = xnt.INT_L45_REPORT_FIXED
INT_L45_LOCAL_REPORT = xnt.INT_L45_LOCAL_REPORT

BROADCAST_MAC = ":".join(["ff"] * 6)
MAC_MASK = ":".join(["ff"] * 6)
MCAST_MAC = "01:00:5e:00:00:00"
MCAST_MASK = "ff:ff:ff:80:00:00"
SWITCH_MAC = "00:00:00:00:aa:01"
SWITCH_IPV4 = "192.168.0.1"

ZERO_MAC = "00:00:00:00:00:00"
HOST1_MAC = "00:00:00:00:00:01"
HOST2_MAC = "00:00:00:00:00:02"
HOST3_MAC = "00:00:00:00:00:03"

HOST1_IPV4 = "10.0.1.1"
HOST2_IPV4 = "10.0.2.1"
HOST3_IPV4 = "10.0.3.1"
HOST4_IPV4 = "10.0.4.1"
S1U_SGW_IPV4 = "140.0.0.2"
S1U_ENB_IPV4 = "119.0.0.10"
S1U_ENB_MAC = "00:00:00:00:00:eb"
UE_IPV4 = "16.255.255.252"
DEFAULT_ROUTE_IPV4 = "0.0.0.0"
PREFIX_DEFAULT_ROUTE = 0
PREFIX_SUBNET = 24
PREFIX_HOST = 32

DBUF_MAC = "00:00:00:0d:b0:0f"
DBUF_IPV4 = "141.0.0.1"
DBUF_DRAIN_DST_IPV4 = "142.0.0.1"
DBUF_FAR_ID = 1023
DBUF_TEID = 0

CPU_LOOPBACK_FAKE_ETHERNET_LENGTH = 14

PDR_COUNTER_INGRESS = "FabricIngress.spgw.pdr_counter"
PDR_COUNTER_EGRESS = "FabricEgress.spgw.pdr_counter"

SPGW_IFACE_ACCESS = 1
SPGW_IFACE_CORE = 2
SPGW_IFACE_FROM_DBUF = 3

VLAN_ID_1 = 100
VLAN_ID_2 = 200
VLAN_ID_3 = 300
DEFAULT_VLAN = 4094

MPLS_LABEL_1 = 100
MPLS_LABEL_2 = 200

UPLINK_TEID = 0xEEFFC0F0
DOWNLINK_TEID = 0xEEFFC0F1
UPLINK_PDR_CTR_IDX = 1
DOWNLINK_PDR_CTR_IDX = 2
UPLINK_FAR_ID = 23
DOWNLINK_FAR_ID = 24

# INT instructions
INT_SWITCH_ID = 1 << 15
INT_IG_EG_PORT = 1 << 14
INT_HOP_LATENCY = 1 << 13
INT_QUEUE_OCCUPANCY = 1 << 12
INT_IG_TSTAMP = 1 << 11
INT_EG_TSTAMP = 1 << 10
INT_QUEUE_CONGESTION = 1 << 9
INT_EG_PORT_TX = 1 << 8
INT_ALL_INSTRUCTIONS = [
    INT_SWITCH_ID,
    INT_IG_EG_PORT,
    INT_HOP_LATENCY,
    INT_QUEUE_OCCUPANCY,
    INT_IG_TSTAMP,
    INT_EG_TSTAMP,
    INT_QUEUE_CONGESTION,
    INT_EG_PORT_TX,
]

INT_INS_TO_NAME = {
    INT_SWITCH_ID: "switch_id",
    INT_IG_EG_PORT: "ig_eg_port",
    INT_HOP_LATENCY: "hop_latency",
    INT_QUEUE_OCCUPANCY: "queue_occupancy",
    INT_IG_TSTAMP: "ig_tstamp",
    INT_EG_TSTAMP: "eg_tstamp",
    INT_QUEUE_CONGESTION: "queue_congestion",
    INT_EG_PORT_TX: "eg_port_tx",
}

INT_REPORT_MIRROR_IDS = [300, 301, 302, 303]
RECIRCULATE_PORTS = [68, 196, 324, 452]
SWITCH_ID = 1
INT_REPORT_PORT = 32766
NPROTO_ETHERNET = 0
NPROTO_TELEMETRY_DROP_HEADER = 1
NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2
bind_layers(UDP, INT_L45_REPORT_FIXED, dport=INT_REPORT_PORT)
bind_layers(
    INT_L45_REPORT_FIXED,
    INT_L45_LOCAL_REPORT,
    nproto=NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER,
)
bind_layers(INT_L45_LOCAL_REPORT, Ether)

INT_COLLECTOR_MAC = "00:1e:67:d2:ee:ee"
INT_COLLECTOR_IPV4 = "192.168.99.254"

INT_REPORT_TYPE_LOCAL = 1

PPPOE_CODE_SESSION_STAGE = 0x00

PPPOED_CODE_PADI = 0x09
PPPOED_CODE_PADO = 0x07
PPPOED_CODE_PADR = 0x19
PPPOED_CODE_PADS = 0x65
PPPOED_CODE_PADT = 0xA7

PPPOED_CODES = (
    PPPOED_CODE_PADI,
    PPPOED_CODE_PADO,
    PPPOED_CODE_PADR,
    PPPOED_CODE_PADS,
    PPPOED_CODE_PADT,
)

# Mirror types
MIRROR_TYPE_INT_REPORT = 1

# Bridged metadata type
BRIDGED_MD_TYPE_EGRESS_MIRROR = 2

# Size for different headers
if testutils.test_param_get("profile") == "fabric-spgw-int":
    BMD_BYTES = 51
elif testutils.test_param_get("profile") == "fabric-spgw":
    BMD_BYTES = 50
elif testutils.test_param_get("profile") == "fabric-int":
    BMD_BYTES = 28
else:
    BMD_BYTES = 27  # fabric
IP_HDR_BYTES = 20
UDP_HDR_BYTES = 8
GTP_HDR_BYTES = 8


class GTPU(Packet):
    name = "GTP-U Header"
    fields_desc = [
        BitField("version", 1, 3),
        BitField("PT", 1, 1),
        BitField("reserved", 0, 1),
        BitField("E", 0, 1),
        BitField("S", 0, 1),
        BitField("PN", 0, 1),
        ByteField("gtp_type", 255),
        ShortField("length", None),
        IntField("teid", 0),
    ]

    def post_build(self, pkt, payload):
        pkt += payload
        # Set the length field if it is unset
        if self.length is None:
            length = len(pkt) - 8
            pkt = pkt[:2] + struct.pack("!H", length) + pkt[4:]
        return pkt


# Register our GTPU header with scapy for dissection
bind_layers(UDP, GTPU, dport=UDP_GTP_PORT)
bind_layers(GTPU, IP)


def pkt_mac_swap(pkt):
    orig_dst = pkt[Ether].dst
    pkt[Ether].dst = pkt[Ether].src
    pkt[Ether].src = orig_dst
    return pkt


def pkt_route(pkt, mac_dst):
    new_pkt = pkt.copy()
    new_pkt[Ether].src = pkt[Ether].dst
    new_pkt[Ether].dst = mac_dst
    return new_pkt


def pkt_add_vlan(pkt, vlan_vid=10, vlan_pcp=0, dl_vlan_cfi=0):
    return (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
        / Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
        / pkt[Ether].payload
    )


def pkt_add_inner_vlan(pkt, vlan_vid=10, vlan_pcp=0, dl_vlan_cfi=0):
    assert Dot1Q in pkt
    return (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=ETH_TYPE_VLAN)
        / Dot1Q(prio=pkt[Dot1Q].prio, id=pkt[Dot1Q].id, vlan=pkt[Dot1Q].vlan)
        / Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
        / pkt[Dot1Q].payload
    )


def pkt_add_pppoe(pkt, type, code, session_id):
    return (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
        / PPPoE(version=1, type=type, code=code, sessionid=session_id)
        / PPP()
        / pkt[Ether].payload
    )


def pkt_add_mpls(pkt, label, ttl, cos=0, s=1):
    return (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
        / MPLS(label=label, cos=cos, s=s, ttl=ttl)
        / pkt[Ether].payload
    )


def pkt_add_gtp(
    pkt,
    out_ipv4_src,
    out_ipv4_dst,
    teid,
    sport=DEFAULT_GTP_TUNNEL_SPORT,
    dport=UDP_GTP_PORT,
):
    payload = pkt[Ether].payload
    return (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
        / IP(src=out_ipv4_src, dst=out_ipv4_dst, tos=0, id=0x1513, flags=0, frag=0,)
        / UDP(sport=sport, dport=dport, chksum=0)
        / GTPU(teid=teid)
        / payload
    )


def pkt_remove_vlan(pkt):
    assert Dot1Q in pkt
    payload = pkt[Dot1Q:1].payload
    return (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=pkt[Dot1Q:1].type) / payload
    )


def pkt_decrement_ttl(pkt):
    if IP in pkt:
        pkt[IP].ttl -= 1
    return pkt


class FabricTest(P4RuntimeTest):

    # An IP pool which will be shared by all FabricTests
    # Start from 172.16.0.0
    next_single_use_ips = 0xAC100000

    def __init__(self):
        super(FabricTest, self).__init__()
        self.next_mbr_id = 1

    def get_next_mbr_id(self):
        mbr_id = self.next_mbr_id
        self.next_mbr_id = self.next_mbr_id + 1
        return mbr_id

    def get_single_use_ip(self):
        FabricTest.next_single_use_ips += 1
        return socket.inet_ntoa(struct.pack("!I", FabricTest.next_single_use_ips))

    def setUp(self):
        super(FabricTest, self).setUp()
        self.port1 = self.swports(1)
        self.port2 = self.swports(2)
        self.port3 = self.swports(3)
        self.port4 = self.swports(4)
        self.setup_switch_info()

    def tearDown(self):
        self.reset_switch_info()
        P4RuntimeTest.tearDown(self)

    def build_packet_out(self, pkt, port, cpu_loopback_mode=CPU_LOOPBACK_MODE_DISABLED):
        packet_out = p4runtime_pb2.PacketOut()
        packet_out.payload = bytes(pkt)
        # egress_port
        port_md = packet_out.metadata.add()
        port_md.metadata_id = 1
        port_md.value = stringify(port, 2)
        # cpu_loopback_mode
        cpu_loopback_mode_md = packet_out.metadata.add()
        cpu_loopback_mode_md.metadata_id = 2
        cpu_loopback_mode_md.value = stringify(cpu_loopback_mode, 1)
        # pad0
        pad0_md = packet_out.metadata.add()
        pad0_md.metadata_id = 3
        pad0_md.value = stringify(0, 1)
        # ether type
        ether_type_md = packet_out.metadata.add()
        ether_type_md.metadata_id = 4
        ether_type_md.value = stringify(ETH_TYPE_PACKET_OUT, 2)
        return packet_out

    def setup_int(self):
        self.send_request_add_entry_to_action(
            "int_egress.int_prep",
            None,
            "int_egress.int_transit",
            [("switch_id", stringify(1, 4))],
        )

        req = self.get_new_write_request()
        for i in range(16):
            base = "int_set_header_0003_i"
            mf = self.Exact("hdr.int_header.instruction_mask_0003", stringify(i, 1))
            action = "int_metadata_insert." + base + str(i)
            self.push_update_add_entry_to_action(
                req, "int_metadata_insert.int_inst_0003", [mf], action, []
            )
        self.write_request(req)

        req = self.get_new_write_request()
        for i in range(16):
            base = "int_set_header_0407_i"
            mf = self.Exact("hdr.int_header.instruction_mask_0407", stringify(i, 1))
            action = "int_metadata_insert." + base + str(i)
            self.push_update_add_entry_to_action(
                req, "int_metadata_insert.int_inst_0407", [mf], action, []
            )
        self.write_request(req)

    def setup_port(
        self, port_id, vlan_id, tagged=False, double_tagged=False, inner_vlan_id=0,
    ):
        if double_tagged:
            self.set_ingress_port_vlan(
                ingress_port=port_id,
                vlan_id=vlan_id,
                vlan_valid=True,
                inner_vlan_id=inner_vlan_id,
            )
        elif tagged:
            self.set_ingress_port_vlan(
                ingress_port=port_id, vlan_id=vlan_id, vlan_valid=True
            )
            self.set_egress_vlan(egress_port=port_id, vlan_id=vlan_id, push_vlan=True)
        else:
            self.set_ingress_port_vlan(
                ingress_port=port_id, vlan_valid=False, internal_vlan_id=vlan_id,
            )
            self.set_egress_vlan(egress_port=port_id, vlan_id=vlan_id, push_vlan=False)

    @tvcreate("setup/setup_switch_info")
    def setup_switch_info(self):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_action(
            req,
            "FabricEgress.pkt_io_egress.switch_info",
            None,
            "FabricEgress.pkt_io_egress.set_switch_info",
            [("cpu_port", stringify(self.cpu_port, 2))],
        )
        return req, self.write_request(req, store=False)

    @tvcreate("teardown/reset_switch_info")
    def reset_switch_info(self):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_action(
            req, "FabricEgress.pkt_io_egress.switch_info", None, "nop", []
        )
        return req, self.write_request(req)

    def set_ingress_port_vlan(
        self,
        ingress_port,
        vlan_valid=False,
        vlan_id=0,
        internal_vlan_id=0,
        inner_vlan_id=None,
    ):
        ingress_port_ = stringify(ingress_port, 2)
        vlan_valid_ = b"\x01" if vlan_valid else b"\x00"
        vlan_id_ = stringify(vlan_id, 2)
        vlan_id_mask_ = stringify(4095 if vlan_valid else 0, 2)
        new_vlan_id_ = stringify(internal_vlan_id, 2)
        action_name = "permit" if vlan_valid else "permit_with_internal_vlan"
        action_params = [] if vlan_valid else [("vlan_id", new_vlan_id_)]
        matches = [
            self.Exact("ig_port", ingress_port_),
            self.Exact("vlan_is_valid", vlan_valid_),
        ]
        if vlan_id_mask_ != b"\x00\x00":
            matches.append(self.Ternary("vlan_id", vlan_id_, vlan_id_mask_))
        if inner_vlan_id is not None:
            # Match on inner_vlan, only when explicitly requested
            inner_vlan_id_ = stringify(inner_vlan_id, 2)
            inner_vlan_id_mask_ = stringify(4095, 2)
            matches.append(
                self.Ternary("inner_vlan_id", inner_vlan_id_, inner_vlan_id_mask_)
            )

        return self.send_request_add_entry_to_action(
            "filtering.ingress_port_vlan",
            matches,
            "filtering." + action_name,
            action_params,
            DEFAULT_PRIORITY,
        )

    def set_egress_vlan(self, egress_port, vlan_id, push_vlan=False):
        egress_port = stringify(egress_port, 2)
        vlan_id = stringify(vlan_id, 2)
        action_name = "push_vlan" if push_vlan else "pop_vlan"
        self.send_request_add_entry_to_action(
            "egress_next.egress_vlan",
            [self.Exact("vlan_id", vlan_id), self.Exact("eg_port", egress_port)],
            "egress_next." + action_name,
            [],
        )

    def set_forwarding_type(
        self,
        ingress_port,
        eth_dstAddr,
        eth_dstMask=MAC_MASK,
        ethertype=ETH_TYPE_IPV4,
        fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
    ):
        ingress_port_ = stringify(ingress_port, 2)
        eth_dstAddr_ = mac_to_binary(eth_dstAddr)
        eth_mask_ = mac_to_binary(eth_dstMask)
        if ethertype == ETH_TYPE_IPV4:
            ethertype_ = stringify(0, 2)
            ethertype_mask_ = stringify(0, 2)
            ip_eth_type = stringify(ethertype, 2)
        elif ethertype == ETH_TYPE_MPLS_UNICAST:
            ethertype_ = stringify(ETH_TYPE_MPLS_UNICAST, 2)
            ethertype_mask_ = stringify(0xFFFF, 2)
            # FIXME: this will work only for MPLS+IPv4 traffic
            ip_eth_type = stringify(ETH_TYPE_IPV4, 2)
        else:
            # TODO: what should we match on? I should never reach this point.
            return
        fwd_type_ = stringify(fwd_type, 1)
        matches = [
            self.Exact("ig_port", ingress_port_),
            self.Ternary("eth_dst", eth_dstAddr_, eth_mask_),
            self.Exact("ip_eth_type", ip_eth_type),
        ]
        if ethertype_mask_ != b"\x00\x00":
            matches.append(self.Ternary("eth_type", ethertype_, ethertype_mask_))
        self.send_request_add_entry_to_action(
            "filtering.fwd_classifier",
            matches,
            "filtering.set_forwarding_type",
            [("fwd_type", fwd_type_)],
            priority=DEFAULT_PRIORITY,
        )

    def add_bridging_entry(
        self,
        vlan_id,
        eth_dstAddr,
        eth_dstAddr_mask,
        next_id,
        priority=DEFAULT_PRIORITY,
    ):
        vlan_id_ = stringify(vlan_id, 2)
        mk = [self.Exact("vlan_id", vlan_id_)]
        if eth_dstAddr is not None and eth_dstAddr_mask is not None:
            eth_dstAddr_ = mac_to_binary(eth_dstAddr)
            eth_dstAddr_mask_ = mac_to_binary(eth_dstAddr_mask)
            mk.append(self.Ternary("eth_dst", eth_dstAddr_, eth_dstAddr_mask_))
        next_id_ = stringify(next_id, 4)
        return self.send_request_add_entry_to_action(
            "forwarding.bridging",
            mk,
            "forwarding.set_next_id_bridging",
            [("next_id", next_id_)],
            priority,
        )

    def read_bridging_entry(self, vlan_id, eth_dstAddr, eth_dstAddr_mask):
        vlan_id_ = stringify(vlan_id, 2)
        mk = [self.Exact("vlan_id", vlan_id_)]
        if eth_dstAddr is not None:
            eth_dstAddr_ = mac_to_binary(eth_dstAddr)
            eth_dstAddr_mask_ = mac_to_binary(eth_dstAddr_mask)
            mk.append(self.Ternary("eth_dst", eth_dstAddr_, eth_dstAddr_mask_))
        return self.read_table_entry("forwarding.bridging", mk, DEFAULT_PRIORITY)

    def add_forwarding_routing_v4_entry(self, ipv4_dstAddr, ipv4_pLen, next_id):
        ipv4_dstAddr_ = ipv4_to_binary(ipv4_dstAddr)
        next_id_ = stringify(next_id, 4)
        self.send_request_add_entry_to_action(
            "forwarding.routing_v4",
            [self.Lpm("ipv4_dst", ipv4_dstAddr_, ipv4_pLen)],
            "forwarding.set_next_id_routing_v4",
            [("next_id", next_id_)],
        )

    def add_forwarding_mpls_entry(self, label, next_id):
        label_ = stringify(label, 3)
        next_id_ = stringify(next_id, 4)
        self.send_request_add_entry_to_action(
            "forwarding.mpls",
            [self.Exact("mpls_label", label_)],
            "forwarding.pop_mpls_and_next",
            [("next_id", next_id_)],
        )

    def add_forwarding_acl_punt_to_cpu(self, eth_type=None, priority=DEFAULT_PRIORITY):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask_ = stringify(0xFFFF, 2)
        return self.send_request_add_entry_to_action(
            "acl.acl",
            [self.Ternary("eth_type", eth_type_, eth_type_mask_)],
            "acl.punt_to_cpu",
            [],
            priority,
        )

    def read_forwarding_acl_punt_to_cpu(self, eth_type=None, priority=DEFAULT_PRIORITY):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask_ = stringify(0xFFFF, 2)
        mk = [self.Ternary("eth_type", eth_type_, eth_type_mask_)]
        return self.read_table_entry("acl.acl", mk, priority)

    def add_forwarding_acl_copy_to_cpu(self, eth_type=None):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask = stringify(0xFFFF, 2)
        self.send_request_add_entry_to_action(
            "acl.acl",
            [self.Ternary("eth_type", eth_type_, eth_type_mask)],
            "acl.copy_to_cpu",
            [],
            DEFAULT_PRIORITY,
        )

    def add_forwarding_acl_set_clone_session_id(
        self, eth_type=None, clone_group_id=None
    ):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask = stringify(0xFFFF, 2)
        clone_group_id_ = stringify(clone_group_id, 4)
        self.send_request_add_entry_to_action(
            "acl.acl",
            [self.Ternary("eth_type", eth_type_, eth_type_mask)],
            "acl.set_clone_session_id",
            [("clone_id", clone_group_id_)],
            DEFAULT_PRIORITY,
        )

    def add_xconnect(self, next_id, port1, port2):
        next_id_ = stringify(next_id, 4)
        port1_ = stringify(port1, 2)
        port2_ = stringify(port2, 2)
        for (inport, outport) in ((port1_, port2_), (port2_, port1_)):
            self.send_request_add_entry_to_action(
                "next.xconnect",
                [self.Exact("next_id", next_id_), self.Exact("ig_port", inport)],
                "next.output_xconnect",
                [("port_num", outport)],
            )

    def add_next_output(self, next_id, egress_port):
        egress_port_ = stringify(egress_port, 2)
        self.add_next_hashed_indirect_action(
            next_id, "next.output_hashed", [("port_num", egress_port_)]
        )

    def add_next_output_simple(self, next_id, egress_port):
        next_id_ = stringify(next_id, 4)
        egress_port_ = stringify(egress_port, 2)
        self.send_request_add_entry_to_action(
            "next.simple",
            [self.Exact("next_id", next_id_)],
            "next.output_simple",
            [("port_num", egress_port_)],
        )

    def add_next_multicast(self, next_id, mcast_group_id):
        next_id_ = stringify(next_id, 4)
        mcast_group_id_ = stringify(mcast_group_id, 2)
        self.send_request_add_entry_to_action(
            "next.multicast",
            [self.Exact("next_id", next_id_)],
            "next.set_mcast_group_id",
            [("group_id", mcast_group_id_)],
        )

    def add_next_multicast_simple(self, next_id, mcast_group_id):
        next_id_ = stringify(next_id, 4)
        mcast_group_id_ = stringify(mcast_group_id, 2)
        self.send_request_add_entry_to_action(
            "next.multicast",
            [self.Exact("next_id", next_id_)],
            "next.set_mcast_group",
            [("gid", mcast_group_id_)],
        )

    def add_next_routing(self, next_id, egress_port, smac, dmac):
        egress_port_ = stringify(egress_port, 2)
        smac_ = mac_to_binary(smac)
        dmac_ = mac_to_binary(dmac)
        self.add_next_hashed_group_action(
            next_id,
            egress_port,
            [
                [
                    "next.routing_hashed",
                    [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_)],
                ]
            ],
        )

    def add_next_routing_simple(self, next_id, egress_port, smac, dmac):
        next_id_ = stringify(next_id, 4)
        egress_port_ = stringify(egress_port, 2)
        smac_ = mac_to_binary(smac)
        dmac_ = mac_to_binary(dmac)
        self.send_request_add_entry_to_action(
            "next.simple",
            [self.Exact("next_id", next_id_)],
            "next.routing_simple",
            [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_)],
        )

    def add_next_vlan(self, next_id, new_vlan_id):
        next_id_ = stringify(next_id, 4)
        vlan_id_ = stringify(new_vlan_id, 2)
        self.send_request_add_entry_to_action(
            "next.next_vlan",
            [self.Exact("next_id", next_id_)],
            "next.set_vlan",
            [("vlan_id", vlan_id_)],
        )

    def add_next_double_vlan(self, next_id, new_vlan_id, new_inner_vlan_id):
        next_id_ = stringify(next_id, 4)
        vlan_id_ = stringify(new_vlan_id, 2)
        inner_vlan_id_ = stringify(new_inner_vlan_id, 2)
        self.send_request_add_entry_to_action(
            "next.next_vlan",
            [self.Exact("next_id", next_id_)],
            "next.set_double_vlan",
            [("outer_vlan_id", vlan_id_), ("inner_vlan_id", inner_vlan_id_)],
        )

    def add_next_hashed_indirect_action(self, next_id, action_name, params):
        next_id_ = stringify(next_id, 4)
        mbr_id = self.get_next_mbr_id()
        self.send_request_add_member(
            "FabricIngress.next.hashed_profile", mbr_id, action_name, params
        )
        self.send_request_add_entry_to_member(
            "next.hashed", [self.Exact("next_id", next_id_)], mbr_id
        )

    # actions is a tuple (action_name, param_tuples)
    # params_tuples contains a tuple for each param (param_name, param_value)
    def add_next_hashed_group_action(self, next_id, grp_id, actions=()):
        next_id_ = stringify(next_id, 4)
        mbr_ids = []
        for action in actions:
            mbr_id = self.get_next_mbr_id()
            mbr_ids.append(mbr_id)
            self.send_request_add_member(
                "FabricIngress.next.hashed_profile", mbr_id, *action
            )
        self.send_request_add_group(
            "FabricIngress.next.hashed_profile",
            grp_id,
            grp_size=len(mbr_ids),
            mbr_ids=mbr_ids,
        )
        self.send_request_add_entry_to_group(
            "next.hashed", [self.Exact("next_id", next_id_)], grp_id
        )

    # next_hops is a list of tuples (egress_port, smac, dmac)
    def add_next_routing_group(self, next_id, grp_id, next_hops=None):
        actions = []
        if next_hops is not None:
            for (egress_port, smac, dmac) in next_hops:
                egress_port_ = stringify(egress_port, 2)
                smac_ = mac_to_binary(smac)
                dmac_ = mac_to_binary(dmac)
                actions.append(
                    [
                        "next.routing_hashed",
                        [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_)],
                    ]
                )
        self.add_next_hashed_group_action(next_id, grp_id, actions)

    def add_next_mpls_routing(self, next_id, egress_port, smac, dmac, label):
        egress_port_ = stringify(egress_port, 2)
        smac_ = mac_to_binary(smac)
        dmac_ = mac_to_binary(dmac)
        label_ = stringify(label, 3)
        self.add_next_hashed_indirect_action(
            next_id,
            "next.mpls_routing_hashed",
            [
                ("port_num", egress_port_),
                ("smac", smac_),
                ("dmac", dmac_),
                ("label", label_),
            ],
        )

    def add_next_mpls_routing_simple(self, next_id, egress_port, smac, dmac, label):
        next_id_ = stringify(next_id, 4)
        egress_port_ = stringify(egress_port, 2)
        smac_ = mac_to_binary(smac)
        dmac_ = mac_to_binary(dmac)
        label_ = stringify(label, 3)
        self.send_request_add_entry_to_action(
            "next.simple",
            [self.Exact("next_id", next_id_)],
            "next.mpls_routing_simple",
            [
                ("port_num", egress_port_),
                ("smac", smac_),
                ("dmac", dmac_),
                ("label", label_),
            ],
        )

    # next_hops is a list of tuples (egress_port, smac, dmac)
    def add_next_mpls_routing_group(self, next_id, grp_id, next_hops=None):
        actions = []
        if next_hops is not None:
            for (egress_port, smac, dmac, label) in next_hops:
                egress_port_ = stringify(egress_port, 2)
                smac_ = mac_to_binary(smac)
                dmac_ = mac_to_binary(dmac)
                label_ = stringify(label, 3)
                actions.append(
                    [
                        "next.mpls_routing_hashed",
                        [
                            ("port_num", egress_port_),
                            ("smac", smac_),
                            ("dmac", dmac_),
                            ("label", label_),
                        ],
                    ]
                )
        self.add_next_hashed_group_action(next_id, grp_id, actions)

    def write_mcast_group(self, group_id, replicas, update_type):
        req = self.get_new_write_request()
        update = req.updates.add()
        update.type = update_type
        pre_entry = update.entity.packet_replication_engine_entry
        mg_entry = pre_entry.multicast_group_entry
        mg_entry.multicast_group_id = group_id
        for node_id, port in replicas:
            replica = mg_entry.replicas.add()
            replica.egress_port = port
            replica.instance = node_id
        return req, self.write_request(req)

    def add_mcast_group(self, group_id, replicas):
        return self.write_mcast_group(group_id, replicas, p4runtime_pb2.Update.INSERT)

    def modify_mcast_group(self, group_id, replicas):
        return self.write_mcast_group(group_id, replicas, p4runtime_pb2.Update.MODIFY)

    def delete_mcast_group(self, group_id):
        return self.write_mcast_group(group_id, [], p4runtime_pb2.Update.DELETE)

    def add_clone_group(self, clone_id, ports):
        req = self.get_new_write_request()
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        pre_entry = update.entity.packet_replication_engine_entry
        clone_entry = pre_entry.clone_session_entry
        clone_entry.session_id = clone_id
        clone_entry.class_of_service = 0
        clone_entry.packet_length_bytes = 0
        for port in ports:
            replica = clone_entry.replicas.add()
            replica.egress_port = port
            replica.instance = 0  # set to 0 because we don't support it yet.
        return req, self.write_request(req)

    def add_next_hashed_group_member(self, action_name, params):
        mbr_id = self.get_next_mbr_id()
        return self.send_request_add_member(
            "FabricIngress.next.hashed_profile", mbr_id, action_name, params,
        )

    def add_next_hashed_group(self, grp_id, mbr_ids):
        return self.send_request_add_group(
            "FabricIngress.next.hashed_profile",
            grp_id,
            grp_size=len(mbr_ids),
            mbr_ids=mbr_ids,
        )

    def modify_next_hashed_group(self, grp_id, mbr_ids, grp_size):
        return self.send_request_modify_group(
            "FabricIngress.next.hashed_profile", grp_id, grp_size, mbr_ids,
        )

    def read_next_hashed_group_member(self, mbr_id):
        return self.read_action_profile_member(
            "FabricIngress.next.hashed_profile", mbr_id
        )

    def read_next_hashed_group(self, group_id):
        return self.read_action_profile_group(
            "FabricIngress.next.hashed_profile", group_id
        )

    def verify_next_hashed_group(self, group_id, expected_action_profile_group):
        return self.verify_action_profile_group(
            "FabricIngress.next.hashed_profile",
            group_id,
            expected_action_profile_group,
        )

    def read_mcast_group(self, group_id):
        req = self.get_new_read_request()
        entity = req.entities.add()
        multicast_group = entity.packet_replication_engine_entry.multicast_group_entry
        multicast_group.multicast_group_id = group_id

        for entity in self.read_request(req):
            if entity.HasField("packet_replication_engine_entry"):
                pre_entry = entity.packet_replication_engine_entry
                if pre_entry.HasField("multicast_group_entry"):
                    return pre_entry.multicast_group_entry
        return None

    def verify_mcast_group(self, group_id, expected_multicast_group):
        return self.verify_multicast_group(group_id, expected_multicast_group)


class BridgingTest(FabricTest):
    def runBridgingTest(self, tagged1, tagged2, pkt):
        vlan_id = 10
        mac_src = pkt[Ether].src
        mac_dst = pkt[Ether].dst
        self.setup_port(self.port1, vlan_id, tagged1)
        self.setup_port(self.port2, vlan_id, tagged2)
        # miss on filtering.fwd_classifier => bridging
        self.add_bridging_entry(vlan_id, mac_src, MAC_MASK, 10)
        self.add_bridging_entry(vlan_id, mac_dst, MAC_MASK, 20)
        self.add_next_output(10, self.port1)
        self.add_next_output(20, self.port2)

        exp_pkt = pkt.copy()
        pkt2 = pkt_mac_swap(pkt.copy())
        exp_pkt2 = pkt2.copy()

        if tagged1:
            pkt = pkt_add_vlan(pkt, vlan_vid=vlan_id)
            exp_pkt2 = pkt_add_vlan(exp_pkt2, vlan_vid=vlan_id)

        if tagged2:
            pkt2 = pkt_add_vlan(pkt2, vlan_vid=vlan_id)
            exp_pkt = pkt_add_vlan(exp_pkt, vlan_vid=vlan_id)

        self.send_packet(self.port1, pkt)
        self.send_packet(self.port2, pkt2)
        self.verify_each_packet_on_each_port(
            [exp_pkt, exp_pkt2], [self.port2, self.port1]
        )


class BridgingPriorityTest(FabricTest):
    def runBridgingPriorityTest(self):
        low_priority = 5
        high_priority = 100

        vlan_id = 10
        next_id = vlan_id
        mcast_group_id = vlan_id
        mac_dst = HOST2_MAC
        all_ports = [self.port1, self.port2, self.port3]
        for port in all_ports:
            self.setup_port(port, vlan_id, False)

        # Add unicast bridging rule
        self.add_bridging_entry(vlan_id, mac_dst, MAC_MASK, 20, high_priority)
        self.add_next_output(20, self.port2)

        # Add broadcast bridging rule
        self.add_bridging_entry(vlan_id, None, None, next_id, low_priority)
        self.add_next_multicast(next_id, mcast_group_id)
        # Add the multicast group, here we use instance id 1 by default
        replicas = [(1, port) for port in all_ports]
        self.add_mcast_group(mcast_group_id, replicas)

        # Create packet with unicast dst_mac. This packet should be send to
        # port 2 only
        pkt = testutils.simple_eth_packet(eth_dst=HOST2_MAC)
        exp_pkt = pkt.copy()
        self.send_packet(self.port1, pkt)
        self.verify_packet(exp_pkt, self.port2)
        self.verify_no_other_packets()

        # Create packet with unknown dst_mac. This packet should be broadcasted
        pkt = testutils.simple_eth_packet(eth_dst="ff:ff:ff:ff:ff:ff")
        exp_pkt = pkt.copy()
        self.send_packet(self.port1, pkt)
        self.verify_packet(exp_pkt, self.port2)
        self.verify_packet(exp_pkt, self.port3)
        self.verify_no_other_packets()


class DoubleTaggedBridgingTest(FabricTest):
    def runDoubleTaggedBridgingTest(self, pkt):
        vlan_id = 10
        inner_vlan_id = 11
        mac_src = pkt[Ether].src
        mac_dst = pkt[Ether].dst
        self.setup_port(self.port1, vlan_id, True)
        self.setup_port(self.port2, vlan_id, True)
        # miss on filtering.fwd_classifier => bridging
        self.add_bridging_entry(vlan_id, mac_src, MAC_MASK, 10)
        self.add_bridging_entry(vlan_id, mac_dst, MAC_MASK, 20)
        self.add_next_output(10, self.port1)
        self.add_next_output(20, self.port2)

        pkt = pkt_add_vlan(pkt, vlan_vid=vlan_id)
        pkt = pkt_add_inner_vlan(pkt, vlan_vid=inner_vlan_id)
        pkt2 = pkt_mac_swap(pkt.copy())
        exp_pkt = pkt.copy()
        exp_pkt2 = pkt2.copy()

        self.send_packet(self.port1, pkt)
        self.send_packet(self.port2, pkt2)
        self.verify_each_packet_on_each_port(
            [exp_pkt, exp_pkt2], [self.port2, self.port1]
        )


class DoubleVlanXConnectTest(FabricTest):
    def runXConnectTest(self, pkt):
        vlan_id_outer = 100
        vlan_id_inner = 200
        next_id = 99

        self.setup_port(self.port1, vlan_id_outer, tagged=True)
        self.setup_port(self.port2, vlan_id_outer, tagged=True)
        # miss on filtering.fwd_classifier => bridging
        self.add_bridging_entry(vlan_id_outer, None, None, next_id)
        self.add_xconnect(next_id, self.port1, self.port2)

        pkt = pkt_add_vlan(pkt, vlan_vid=vlan_id_inner)
        pkt = pkt_add_vlan(pkt, vlan_vid=vlan_id_outer)
        exp_pkt = pkt.copy()

        self.send_packet(self.port1, pkt)
        self.verify_packet(exp_pkt, self.port2)

        self.send_packet(self.port2, pkt)
        self.verify_packet(exp_pkt, self.port1)


class ArpBroadcastTest(FabricTest):
    def runArpBroadcastTest(self, tagged_ports, untagged_ports):
        vlan_id = 10
        next_id = vlan_id
        mcast_group_id = vlan_id
        all_ports = tagged_ports + untagged_ports
        arp_pkt = testutils.simple_arp_packet(pktlen=MIN_PKT_LEN - 4)
        # Account for VLAN header size in total pktlen
        vlan_arp_pkt = testutils.simple_arp_packet(vlan_vid=vlan_id, pktlen=MIN_PKT_LEN)
        for port in tagged_ports:
            self.set_ingress_port_vlan(port, True, vlan_id, vlan_id)
        for port in untagged_ports:
            self.set_ingress_port_vlan(port, False, 0, vlan_id)
        self.add_bridging_entry(vlan_id, None, None, next_id)
        self.add_forwarding_acl_copy_to_cpu(eth_type=ETH_TYPE_ARP)
        self.add_next_multicast(next_id, mcast_group_id)
        # Add the multicast group, here we use instance id 1 by default
        replicas = [(1, port) for port in all_ports]
        self.add_mcast_group(mcast_group_id, replicas)
        for port in tagged_ports:
            self.set_egress_vlan(port, vlan_id, True)
        for port in untagged_ports:
            self.set_egress_vlan(port, vlan_id, False)

        for inport in all_ports:
            pkt_to_send = vlan_arp_pkt if inport in tagged_ports else arp_pkt
            self.send_packet(inport, pkt_to_send)
            # Pkt should be received on CPU and on all ports, except the ingress one.
            self.verify_packet_in(exp_pkt=pkt_to_send, exp_in_port=inport)
            verify_tagged_ports = set(tagged_ports)
            verify_tagged_ports.discard(inport)
            for tport in verify_tagged_ports:
                self.verify_packet(vlan_arp_pkt, tport)
            verify_untagged_ports = set(untagged_ports)
            verify_untagged_ports.discard(inport)
            for uport in verify_untagged_ports:
                self.verify_packet(arp_pkt, uport)
        self.verify_no_other_packets()


class IPv4UnicastTest(FabricTest):
    def runIPv4UnicastTest(
        self,
        pkt,
        next_hop_mac,
        tagged1=False,
        tagged2=False,
        prefix_len=24,
        exp_pkt=None,
        exp_pkt_base=None,
        next_id=None,
        next_vlan=None,
        is_next_hop_spine=False,
        dst_ipv4=None,
        routed_eth_types=(ETH_TYPE_IPV4,),
        verify_pkt=True,
        with_another_pkt_later=False,
        no_send=False,
        ig_port=None,
        eg_port=None,
    ):
        """
        Execute an IPv4 unicast routing test.
        :param pkt: input packet
        :param next_hop_mac: MAC address of the next hop
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param prefix_len: prefix length to use in the routing table
        :param exp_pkt: expected packet, if none one will be built using the
            input packet
        :param exp_pkt_base: if not none, it will be used to build the expected
            output packet.
        :param next_id: value to use as next ID
        :param next_vlan: value to use as next VLAN
        :param is_next_hop_spine: whether the packet should be routed to the
               spines using MPLS SR
        :param dst_ipv4: if not none, this value will be used as IPv4 dst to
            configure tables
        :param routed_eth_types: eth type values used to configure the
            classifier table to process packets via routing
        :param verify_pkt: whether packets are expected to be forwarded or
            dropped
        :param with_another_pkt_later: another packet(s) will be verified
               outside this function
        :param no_send: if true insert table entries but do not send
            (or verify) packets
        """
        if IP not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv4 test with packet that is not IP")
        if is_next_hop_spine and tagged2:
            self.fail("Cannot do MPLS test with egress port tagged (tagged2)")
        if ig_port is None:
            ig_port = self.port1
        if eg_port is None:
            eg_port = self.port2

        # If the input pkt has a VLAN tag, use that to configure tables.
        pkt_is_tagged = False
        if Dot1Q in pkt:
            vlan1 = pkt[Dot1Q].vlan
            tagged1 = True
            pkt_is_tagged = True
        else:
            vlan1 = VLAN_ID_1

        if is_next_hop_spine:
            # If MPLS test, port2 is assumed to be a spine port, with
            # default vlan untagged.
            vlan2 = DEFAULT_VLAN
            assert not tagged2
        else:
            vlan2 = VLAN_ID_2 if next_vlan is None else next_vlan

        next_id = 100 if next_id is None else next_id
        group_id = next_id
        mpls_label = MPLS_LABEL_2
        if dst_ipv4 is None:
            dst_ipv4 = pkt[IP].dst
        switch_mac = pkt[Ether].dst

        # Setup ports.
        self.setup_port(ig_port, vlan1, tagged1)
        self.setup_port(eg_port, vlan2, tagged2)

        # Forwarding type -> routing v4
        for eth_type in routed_eth_types:
            self.set_forwarding_type(
                ig_port,
                switch_mac,
                ethertype=eth_type,
                fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )

        # Routing entry.
        self.add_forwarding_routing_v4_entry(dst_ipv4, prefix_len, next_id)

        if not is_next_hop_spine:
            self.add_next_routing(next_id, eg_port, switch_mac, next_hop_mac)
            self.add_next_vlan(next_id, vlan2)
        else:
            params = [eg_port, switch_mac, next_hop_mac, mpls_label]
            self.add_next_mpls_routing_group(next_id, group_id, [params])
            self.add_next_vlan(next_id, DEFAULT_VLAN)

        if exp_pkt is None:
            # Build exp pkt using the input one.
            exp_pkt = pkt.copy() if not exp_pkt_base else exp_pkt_base
            exp_pkt = pkt_route(exp_pkt, next_hop_mac)
            if not is_next_hop_spine:
                exp_pkt = pkt_decrement_ttl(exp_pkt)
            if tagged2 and Dot1Q not in exp_pkt:
                exp_pkt = pkt_add_vlan(exp_pkt, vlan_vid=vlan2)
            if is_next_hop_spine:
                exp_pkt = pkt_add_mpls(exp_pkt, label=mpls_label, ttl=DEFAULT_MPLS_TTL)

        if tagged1 and not pkt_is_tagged:
            pkt = pkt_add_vlan(pkt, vlan_vid=vlan1)

        if no_send:
            return

        self.send_packet(ig_port, pkt)

        if verify_pkt:
            self.verify_packet(exp_pkt, eg_port)

        if not with_another_pkt_later:
            self.verify_no_other_packets()


class IPv4MulticastTest(FabricTest):
    def runIPv4MulticastTest(self, pkt, in_port, out_ports, in_vlan, out_vlan):
        if Dot1Q in pkt:
            print("runIPv4MulticastTest() expects untagged packets")
            return

        # Initialize
        internal_in_vlan = in_vlan if in_vlan is not None else 4094
        internal_out_vlan = out_vlan if out_vlan is not None else 4094
        dst_ipv4 = pkt[IP].dst
        prefix_len = 32
        next_id = 1
        mcast_group_id = 1

        # Set port VLAN
        self.setup_port(in_port, internal_in_vlan, in_vlan is not None)
        for out_port in out_ports:
            self.setup_port(out_port, internal_out_vlan, out_vlan is not None)

        # Set forwarding type to IPv4 multicast
        self.set_forwarding_type(
            in_port,
            MCAST_MAC,
            MCAST_MASK,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_IPV4_MULTICAST,
        )

        # Set IPv4 routing table entry
        self.add_forwarding_routing_v4_entry(dst_ipv4, prefix_len, next_id)

        # Add next table entry
        self.add_next_multicast(next_id, mcast_group_id)
        self.add_next_vlan(next_id, internal_out_vlan)

        # Add multicast group
        replicas = [(1, port) for port in out_ports]
        self.add_mcast_group(mcast_group_id, replicas)

        # Prepare packets
        expect_pkt = pkt_decrement_ttl(pkt.copy())
        pkt = pkt_add_vlan(pkt, vlan_vid=in_vlan) if in_vlan is not None else pkt
        expect_pkt = (
            pkt_add_vlan(expect_pkt, vlan_vid=out_vlan)
            if out_vlan is not None
            else expect_pkt
        )

        # Send packets and verify
        self.send_packet(in_port, pkt)
        for out_port in out_ports:
            self.verify_packet(expect_pkt, out_port)
        self.verify_no_other_packets()


class DoubleVlanTerminationTest(FabricTest):
    def runRouteAndPushTest(
        self,
        pkt,
        next_hop_mac,
        prefix_len=24,
        exp_pkt=None,
        next_id=None,
        next_vlan_id=None,
        next_inner_vlan_id=None,
        in_tagged=False,
        dst_ipv4=None,
        routed_eth_types=(ETH_TYPE_IPV4,),
        verify_pkt=True,
    ):
        """
        Route and Push test case. The switch output port is expected to send
        double tagged packets.
        The switch routes the packet to the correct destination and adds the
        double VLAN tag to it.
        :param pkt: input packet
        :param next_hop_mac: MAC address of the next hop
        :param prefix_len: prefix length to use in the routing table
        :param exp_pkt: expected packet, if none one will be built using the
                        input packet
        :param next_id: value to use as next ID
        :param next_vlan_id: the new vlan ID that will be set to the packet
                             after routerd
        :param next_inner_vlan_id: the new inner vlan ID that will be set to
                                   the packet after routerd
        :param in_tagged: the vlan id of the packet when packet enters the
                          pipeline
        :param dst_ipv4: if not none, this value will be used as IPv4 dst to
                         configure tables
        :param routed_eth_types: eth type values used to configure the
                                 classifier table to process packets via
                                 routing
        :param verify_pkt: whether packets are expected to be forwarded or
                           dropped
        """

        if IP not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv4 test with packet that is not IP")

        pkt_is_tagged = False
        if Dot1Q in pkt:
            in_vlan = pkt[Dot1Q].vlan
            in_tagged = True
            pkt_is_tagged = True
        else:
            in_vlan = VLAN_ID_3

        next_id = 100 if next_id is None else next_id

        if dst_ipv4 is None:
            dst_ipv4 = pkt[IP].dst
        switch_mac = pkt[Ether].dst

        # Setup port 1
        self.setup_port(self.port1, vlan_id=in_vlan, tagged=in_tagged)
        # Setup port 2: packets on this port are double tagged packets
        self.setup_port(
            self.port2,
            vlan_id=next_vlan_id,
            double_tagged=True,
            inner_vlan_id=next_inner_vlan_id,
        )

        # Forwarding type -> routing v4
        for eth_type in routed_eth_types:
            self.set_forwarding_type(
                self.port1,
                switch_mac,
                ethertype=eth_type,
                fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )

        # Routing entry.
        self.add_forwarding_routing_v4_entry(dst_ipv4, prefix_len, next_id)
        self.add_next_routing(next_id, self.port2, switch_mac, next_hop_mac)

        # Push double vlan
        self.add_next_double_vlan(next_id, next_vlan_id, next_inner_vlan_id)

        if exp_pkt is None:
            # Build exp pkt using the input one.
            exp_pkt = pkt.copy()
            if in_tagged and pkt_is_tagged:
                exp_pkt = pkt_remove_vlan(exp_pkt, in_vlan)
            exp_pkt = pkt_add_vlan(exp_pkt, next_vlan_id)
            exp_pkt = pkt_add_inner_vlan(exp_pkt, next_inner_vlan_id)
            exp_pkt = pkt_route(exp_pkt, next_hop_mac)
            exp_pkt = pkt_decrement_ttl(exp_pkt)

        if in_tagged and not pkt_is_tagged:
            pkt = pkt_add_vlan(pkt, vlan_vid=in_vlan)

        self.send_packet(self.port1, pkt)
        if verify_pkt:
            self.verify_packet(exp_pkt, self.port2)
        self.verify_no_other_packets()

    def runPopAndRouteTest(
        self,
        pkt,
        next_hop_mac,
        prefix_len=24,
        exp_pkt=None,
        next_id=None,
        vlan_id=None,
        inner_vlan_id=None,
        out_tagged=False,
        is_next_hop_spine=False,
        dst_ipv4=None,
        routed_eth_types=(ETH_TYPE_IPV4,),
        verify_pkt=True,
    ):
        """
        Pop and Route test case. The switch port expect to receive double
        tagged packets.
        The switch removes both VLAN headers from the packet and routes it to
        the correct destination.
        :param pkt: input packet
        :param next_hop_mac: MAC address of the next hop
        :param prefix_len: prefix length to use in the routing table
        :param exp_pkt: expected packet, if none one will be built using the
                        input packet
        :param next_id: value to use as next ID
        :param vlan_id: the vlan ID that will be add to the test packet
        :param inner_vlan_id: the inner vlan ID that will be add to the test
                              packet
        :param out_tagged: the vlan ID that will be set to the packet after
                           routed, none if untagged
        :param is_next_hop_spine: whether the packet should be routed to the
                                  spines using MPLS SR
        :param dst_ipv4: if not none, this value will be used as IPv4 dst to
                         configure tables
        :param routed_eth_types: eth type values used to configure the
                                 classifier table to process packets via
                                 routing
        :param verify_pkt: whether packets are expected to be forwarded or
                           dropped
        """

        if IP not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv4 test with packet that is not IP")
        if is_next_hop_spine and out_tagged:
            self.fail("Cannot do MPLS test with egress port tagged (out_tagged)")

        if Dot1Q not in pkt:
            pkt = pkt_add_vlan(pkt, vlan_vid=vlan_id)
            pkt = pkt_add_inner_vlan(pkt, vlan_vid=inner_vlan_id)
        else:
            try:
                pkt[Dot1Q:2]
            except IndexError:
                # Add the not added vlan header
                if pkt[Dot1Q:1].vlan == vlan_id:
                    pkt = pkt_add_inner_vlan(pkt, vlan_vid=inner_vlan_id)
                elif pkt[Dot1Q:1].vlan == inner_vlan_id:
                    pkt = pkt_add_vlan(pkt, vlan_vid=vlan_id)
                else:
                    self.fail("Packet should be without VLANs or with correct VLANs")
        if is_next_hop_spine:
            # If MPLS test, egress_port is assumed to be a spine port, with
            # default vlan untagged.
            next_vlan = DEFAULT_VLAN
            assert not out_tagged
        else:
            next_vlan = VLAN_ID_3 if out_tagged else vlan_id
        next_id = 100 if next_id is None else next_id
        group_id = next_id
        mpls_label = MPLS_LABEL_2

        if dst_ipv4 is None:
            dst_ipv4 = pkt[IP].dst
        switch_mac = pkt[Ether].dst

        # Setup port 1: packets on this port are double tagged packets
        self.setup_port(
            self.port1,
            vlan_id=vlan_id,
            double_tagged=True,
            inner_vlan_id=inner_vlan_id,
        )
        # Setup port 2
        self.setup_port(self.port2, vlan_id=next_vlan, tagged=out_tagged)

        # Forwarding type -> routing v4
        for eth_type in routed_eth_types:
            self.set_forwarding_type(
                self.port1,
                switch_mac,
                ethertype=eth_type,
                fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )
        self.add_forwarding_routing_v4_entry(dst_ipv4, prefix_len, next_id)

        if not is_next_hop_spine:
            self.add_next_routing(next_id, self.port2, switch_mac, next_hop_mac)
            self.add_next_vlan(next_id, next_vlan)
        else:
            params = [self.port2, switch_mac, next_hop_mac, mpls_label]
            self.add_next_mpls_routing_group(next_id, group_id, [params])
            self.add_next_vlan(next_id, DEFAULT_VLAN)

        if exp_pkt is None:
            # Build exp pkt using the input one.
            exp_pkt = pkt.copy()
            exp_pkt = pkt_route(exp_pkt, next_hop_mac)
            exp_pkt = pkt_remove_vlan(exp_pkt)
            exp_pkt = pkt_remove_vlan(exp_pkt)
            if not is_next_hop_spine:
                exp_pkt = pkt_decrement_ttl(exp_pkt)
            if out_tagged and Dot1Q not in exp_pkt:
                exp_pkt = pkt_add_vlan(exp_pkt, vlan_vid=next_vlan)
            if is_next_hop_spine:
                exp_pkt = pkt_add_mpls(exp_pkt, label=mpls_label, ttl=DEFAULT_MPLS_TTL)

        self.send_packet(self.port1, pkt)
        if verify_pkt:
            self.verify_packet(exp_pkt, self.port2)
        self.verify_no_other_packets()


class MplsSegmentRoutingTest(FabricTest):
    def runMplsSegmentRoutingTest(self, pkt, dst_mac, next_hop_spine=True):
        if IP not in pkt or Ether not in pkt:
            self.fail("Cannot do MPLS segment routing test with packet that is not IP")
        if Dot1Q in pkt:
            self.fail("Cannot do MPLS segment routing test with VLAN tagged packet")

        next_id = MPLS_LABEL_1
        label = MPLS_LABEL_1
        group_id = MPLS_LABEL_1
        mpls_ttl = DEFAULT_MPLS_TTL
        switch_mac = pkt[Ether].dst

        # Setup ports, both untagged
        self.setup_port(self.port1, DEFAULT_VLAN, False)
        self.setup_port(self.port2, DEFAULT_VLAN, False)
        # Forwarding type -> mpls
        self.set_forwarding_type(
            self.port1,
            switch_mac,
            ethertype=ETH_TYPE_MPLS_UNICAST,
            fwd_type=FORWARDING_TYPE_MPLS,
        )
        # Mpls entry.
        self.add_forwarding_mpls_entry(label, next_id)

        if not next_hop_spine:
            self.add_next_routing(next_id, self.port2, switch_mac, dst_mac)
        else:
            params = [self.port2, switch_mac, dst_mac, label]
            self.add_next_mpls_routing_group(next_id, group_id, [params])

        exp_pkt = pkt.copy()
        pkt = pkt_add_mpls(pkt, label, mpls_ttl)
        exp_pkt[Ether].src = switch_mac
        exp_pkt[Ether].dst = dst_mac
        if not next_hop_spine:
            exp_pkt[IP].ttl = exp_pkt[IP].ttl - 1
        else:
            exp_pkt = pkt_add_mpls(exp_pkt, label, mpls_ttl - 1)

        self.send_packet(self.port1, pkt)
        self.verify_packet(exp_pkt, self.port2)


class PacketOutTest(FabricTest):
    def runPacketOutTest(self, pkt):
        for port in [self.port1, self.port2]:
            self.verify_packet_out(pkt, out_port=port)
        self.verify_no_other_packets()


class PacketInTest(FabricTest):
    def runPacketInTest(self, pkt, eth_type, tagged=False, vlan_id=10):
        self.add_forwarding_acl_punt_to_cpu(eth_type=eth_type)
        for port in [self.port1, self.port2]:
            if tagged:
                self.set_ingress_port_vlan(port, True, vlan_id, vlan_id)
            else:
                self.set_ingress_port_vlan(port, False, 0, vlan_id)
            self.send_packet(port, pkt)
            self.verify_packet_in(pkt, port)
        self.verify_no_other_packets()


class SpgwSimpleTest(IPv4UnicastTest):
    def read_counter(self, c_name, idx):
        counter = self.read_indirect_counter(c_name, idx, typ="BOTH")
        return (counter.data.packet_count, counter.data.byte_count)

    def _add_spgw_iface(self, iface_addr, prefix_len, iface_enum, gtpu_valid):
        req = self.get_new_write_request()

        iface_addr_ = ipv4_to_binary(iface_addr)

        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.interfaces",
            [
                self.Lpm("ipv4_dst_addr", iface_addr_, prefix_len),
                self.Exact("gtpu_is_valid", stringify(int(gtpu_valid), 1)),
            ],
            "FabricIngress.spgw.load_iface",
            [("src_iface", stringify(iface_enum, 1))],
        )
        self.write_request(req)

    def add_ue_pool(self, pool_addr, prefix_len=32):
        self._add_spgw_iface(
            iface_addr=pool_addr,
            prefix_len=prefix_len,
            iface_enum=SPGW_IFACE_CORE,
            gtpu_valid=False,
        )

    def add_s1u_iface(self, s1u_addr, prefix_len=32):
        self._add_spgw_iface(
            iface_addr=s1u_addr,
            prefix_len=prefix_len,
            iface_enum=SPGW_IFACE_ACCESS,
            gtpu_valid=True,
        )

    def add_dbuf_device(
        self,
        dbuf_addr=DBUF_IPV4,
        drain_dst_addr=DBUF_DRAIN_DST_IPV4,
        dbuf_far_id=DBUF_FAR_ID,
        dbuf_teid=DBUF_TEID,
    ):
        # Switch interface for traffic to/from dbuf device
        self._add_spgw_iface(
            iface_addr=drain_dst_addr,
            prefix_len=32,
            iface_enum=SPGW_IFACE_FROM_DBUF,
            gtpu_valid=True,
        )

        # FAR that tunnels to the dbuf device
        return self._add_far(
            dbuf_far_id,
            "FabricIngress.spgw.load_dbuf_far",
            [
                ("drop", stringify(0, 1)),
                ("notify_cp", stringify(0, 1)),
                ("teid", stringify(dbuf_teid, 4)),
                ("tunnel_src_port", stringify(UDP_GTP_PORT, 2)),
                ("tunnel_src_addr", ipv4_to_binary(drain_dst_addr)),
                ("tunnel_dst_addr", ipv4_to_binary(dbuf_addr)),
            ],
        )

    def add_uplink_pdr(self, ctr_id, far_id, teid, tunnel_dst_addr):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.uplink_pdrs",
            [
                self.Exact("teid", stringify(teid, 4)),
                self.Exact("tunnel_ipv4_dst", ipv4_to_binary(tunnel_dst_addr)),
            ],
            "FabricIngress.spgw.load_pdr",
            [
                ("ctr_id", stringify(ctr_id, 2)),
                ("far_id", stringify(far_id, 4)),
                ("needs_gtpu_decap", stringify(1, 1)),
            ],
        )
        self.write_request(req)

    def add_downlink_pdr(self, ctr_id, far_id, ue_addr):
        req = self.get_new_write_request()

        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.downlink_pdrs",
            [self.Exact("ue_addr", ipv4_to_binary(ue_addr))],
            "FabricIngress.spgw.load_pdr",
            [
                ("ctr_id", stringify(ctr_id, 2)),
                ("far_id", stringify(far_id, 4)),
                ("needs_gtpu_decap", stringify(0, 1)),
            ],
        )
        self.write_request(req)

    def _add_far(self, far_id, action_name, action_params):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.fars",
            [self.Exact("far_id", stringify(far_id, 4))],
            action_name,
            action_params,
        )
        self.write_request(req)

    def add_normal_far(self, far_id, drop=False, notify_cp=False):
        return self._add_far(
            far_id,
            "FabricIngress.spgw.load_normal_far",
            [("drop", stringify(drop, 1)), ("notify_cp", stringify(notify_cp, 1))],
        )

    def add_tunnel_far(
        self,
        far_id,
        teid,
        tunnel_src_addr,
        tunnel_dst_addr,
        tunnel_src_port=DEFAULT_GTP_TUNNEL_SPORT,
        drop=False,
        notify_cp=False,
    ):
        return self._add_far(
            far_id,
            "FabricIngress.spgw.load_tunnel_far",
            [
                ("drop", stringify(drop, 1)),
                ("notify_cp", stringify(notify_cp, 1)),
                ("teid", stringify(teid, 4)),
                ("tunnel_src_port", stringify(tunnel_src_port, 2)),
                ("tunnel_src_addr", ipv4_to_binary(tunnel_src_addr)),
                ("tunnel_dst_addr", ipv4_to_binary(tunnel_dst_addr)),
            ],
        )

    def setup_uplink(self, s1u_sgw_addr, teid, ctr_id, far_id=UPLINK_FAR_ID):
        self.add_s1u_iface(s1u_sgw_addr)
        self.add_uplink_pdr(
            ctr_id=ctr_id, far_id=far_id, teid=teid, tunnel_dst_addr=s1u_sgw_addr,
        )
        self.add_normal_far(far_id=far_id)

    def setup_downlink(
        self, s1u_sgw_addr, s1u_enb_addr, teid, ue_addr, ctr_id, far_id=DOWNLINK_FAR_ID,
    ):
        self.add_ue_pool(ue_addr)
        self.add_downlink_pdr(ctr_id=ctr_id, far_id=far_id, ue_addr=ue_addr)
        self.add_tunnel_far(
            far_id=far_id,
            teid=teid,
            tunnel_src_addr=s1u_sgw_addr,
            tunnel_dst_addr=s1u_enb_addr,
        )

    def reset_pdr_counters(self, ctr_idx):
        """Reset the ingress and egress PDR counter packet and byte counts to
        0 for the given index.
        """
        self.write_indirect_counter(PDR_COUNTER_INGRESS, ctr_idx, 0, 0)
        self.write_indirect_counter(PDR_COUNTER_EGRESS, ctr_idx, 0, 0)

    def verify_pdr_counters(
        self,
        ctr_idx,
        exp_ingress_bytes,
        exp_egress_bytes,
        exp_ingress_pkts,
        exp_egress_pkts,
    ):
        """ Verify that the PDR ingress and egress counters for index 'ctr_idx' are now
            'exp_ingress_bytes', 'exp_ingress_pkts' and 'exp_egress_bytes',
            'exp_egress_pkts' respectively upon reading.
        """
        self.verify_indirect_counter(
            PDR_COUNTER_INGRESS, ctr_idx, "BOTH", exp_ingress_bytes, exp_ingress_pkts,
        )
        self.verify_indirect_counter(
            PDR_COUNTER_EGRESS, ctr_idx, "BOTH", exp_egress_bytes, exp_egress_pkts,
        )

    def runUplinkTest(self, ue_out_pkt, tagged1, tagged2, is_next_hop_spine):
        upstream_mac = HOST2_MAC

        gtp_pkt = pkt_add_gtp(
            ue_out_pkt,
            out_ipv4_src=S1U_ENB_IPV4,
            out_ipv4_dst=S1U_SGW_IPV4,
            teid=UPLINK_TEID,
        )
        gtp_pkt[Ether].src = S1U_ENB_MAC
        gtp_pkt[Ether].dst = SWITCH_MAC

        exp_pkt = ue_out_pkt.copy()
        exp_pkt[Ether].src = SWITCH_MAC
        exp_pkt[Ether].dst = upstream_mac
        if not is_next_hop_spine:
            exp_pkt[IP].ttl = exp_pkt[IP].ttl - 1
        else:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)

        self.setup_uplink(
            s1u_sgw_addr=S1U_SGW_IPV4, teid=UPLINK_TEID, ctr_id=UPLINK_PDR_CTR_IDX,
        )

        # Clear SPGW counters before sending the packet
        self.reset_pdr_counters(UPLINK_PDR_CTR_IDX)

        self.runIPv4UnicastTest(
            pkt=gtp_pkt,
            dst_ipv4=ue_out_pkt[IP].dst,
            next_hop_mac=upstream_mac,
            prefix_len=32,
            exp_pkt=exp_pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

        ingress_bytes = len(gtp_pkt) + 4  # FIXME: where does this 4 come from?
        egress_bytes = len(exp_pkt) + BMD_BYTES
        if tagged1:
            ingress_bytes += 4  # length of VLAN header
            egress_bytes += 4  # FIXME: why is this necessary?
        if not tagged2:
            egress_bytes += 4  # FIXME: why?
        if is_next_hop_spine:
            egress_bytes -= 4  # FIXME: ?????
        if self.loopback:
            ingress_bytes += CPU_LOOPBACK_FAKE_ETHERNET_LENGTH
            egress_bytes += CPU_LOOPBACK_FAKE_ETHERNET_LENGTH

        # Verify the Ingress and Egress PDR counters
        self.verify_pdr_counters(UPLINK_PDR_CTR_IDX, ingress_bytes, egress_bytes, 1, 1)

    def runDownlinkTest(self, pkt, tagged1, tagged2, is_next_hop_spine):
        exp_pkt = pkt.copy()
        exp_pkt[Ether].src = SWITCH_MAC
        exp_pkt[Ether].dst = S1U_ENB_MAC
        if not is_next_hop_spine:
            exp_pkt[IP].ttl = exp_pkt[IP].ttl - 1
        exp_pkt = pkt_add_gtp(
            exp_pkt,
            out_ipv4_src=S1U_SGW_IPV4,
            out_ipv4_dst=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
        )
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)

        self.setup_downlink(
            s1u_sgw_addr=S1U_SGW_IPV4,
            s1u_enb_addr=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
            ue_addr=UE_IPV4,
            ctr_id=DOWNLINK_PDR_CTR_IDX,
        )

        # Clear SPGW counters before sending the packet
        self.reset_pdr_counters(DOWNLINK_PDR_CTR_IDX)

        self.runIPv4UnicastTest(
            pkt=pkt,
            dst_ipv4=exp_pkt[IP].dst,
            next_hop_mac=S1U_ENB_MAC,
            prefix_len=32,
            exp_pkt=exp_pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

        ingress_bytes = len(pkt) + 4  # FIXME: where does this 4 come from?
        # Since the counter will use the packet length before the pipeline encaped with
        # GTPU headers, we need to remove it from the expected result.
        egress_bytes = (
            len(exp_pkt) + BMD_BYTES - IP_HDR_BYTES - UDP_HDR_BYTES - GTP_HDR_BYTES
        )
        if tagged1:
            ingress_bytes += 4  # length of VLAN header
            egress_bytes += 4  # FIXME: why is this necessary?
        if not tagged2:
            egress_bytes += 4  # FIXME: why?
        if is_next_hop_spine:
            egress_bytes -= 4  # FIXME: ?????
        if self.loopback:
            ingress_bytes += CPU_LOOPBACK_FAKE_ETHERNET_LENGTH
            egress_bytes += CPU_LOOPBACK_FAKE_ETHERNET_LENGTH

        # Verify the Ingress and Egress PDR counters
        self.verify_pdr_counters(
            DOWNLINK_PDR_CTR_IDX, ingress_bytes, egress_bytes, 1, 1
        )

    def runDownlinkToDbufTest(self, pkt, tagged1, tagged2, is_next_hop_spine):
        exp_pkt = pkt.copy()
        exp_pkt[Ether].src = SWITCH_MAC
        exp_pkt[Ether].dst = DBUF_MAC
        if not is_next_hop_spine:
            exp_pkt[IP].ttl = exp_pkt[IP].ttl - 1
        # add dbuf tunnel
        exp_pkt = pkt_add_gtp(
            exp_pkt,
            out_ipv4_src=DBUF_DRAIN_DST_IPV4,
            out_ipv4_dst=DBUF_IPV4,
            teid=DBUF_TEID,
            sport=UDP_GTP_PORT,
        )
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)

        # Add the UE pool interface and the PDR pointing to the DBUF FAR
        self.add_ue_pool(UE_IPV4)
        self.add_downlink_pdr(
            ctr_id=DOWNLINK_PDR_CTR_IDX, far_id=DBUF_FAR_ID, ue_addr=UE_IPV4
        )

        # Add rules for sending/receiving packets to/from dbuf
        # (receiving isn't done by this test though)
        self.add_dbuf_device(
            dbuf_addr=DBUF_IPV4,
            drain_dst_addr=DBUF_DRAIN_DST_IPV4,
            dbuf_far_id=DBUF_FAR_ID,
            dbuf_teid=DBUF_TEID,
        )

        # Clear SPGW counters before sending the packet
        self.reset_pdr_counters(DOWNLINK_PDR_CTR_IDX)

        self.runIPv4UnicastTest(
            pkt=pkt,
            dst_ipv4=exp_pkt[IP].dst,
            next_hop_mac=DBUF_MAC,
            prefix_len=32,
            exp_pkt=exp_pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

        ingress_bytes = len(pkt) + 4  # FIXME: where does this 4 come from?
        egress_bytes = 0
        if tagged1:
            ingress_bytes += 4  # length of VLAN header
        if self.loopback:
            ingress_bytes += CPU_LOOPBACK_FAKE_ETHERNET_LENGTH

        # Verify the Ingress PDR packet counter increased, but the egress did
        # not.
        self.verify_pdr_counters(
            DOWNLINK_PDR_CTR_IDX, ingress_bytes, egress_bytes, 1, 0
        )

    def runDownlinkFromDbufTest(self, pkt, tagged1, tagged2, is_next_hop_spine):
        """Tests a packet returning from dbuf to be sent to the enodeb.
        Similar to a normal downlink test, but the input is gtpu encapped.
        """
        # The input packet is from dbuf and is GTPU encapsulated
        pkt_from_dbuf = pkt.copy()
        pkt_from_dbuf[Ether].src = DBUF_MAC
        pkt_from_dbuf[Ether].dst = SWITCH_MAC
        pkt_from_dbuf = pkt_add_gtp(
            pkt_from_dbuf,
            out_ipv4_src=DBUF_IPV4,
            out_ipv4_dst=DBUF_DRAIN_DST_IPV4,
            teid=DBUF_TEID,
        )

        # A normal downlink packet to the enodeb is the expected output
        exp_pkt = pkt.copy()
        exp_pkt[Ether].src = SWITCH_MAC
        exp_pkt[Ether].dst = S1U_ENB_MAC
        if not is_next_hop_spine:
            exp_pkt[IP].ttl = exp_pkt[IP].ttl - 1
        exp_pkt = pkt_add_gtp(
            exp_pkt,
            out_ipv4_src=S1U_SGW_IPV4,
            out_ipv4_dst=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
        )
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)

        # Normal downlink rules
        self.setup_downlink(
            s1u_sgw_addr=S1U_SGW_IPV4,
            s1u_enb_addr=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
            ue_addr=UE_IPV4,
            ctr_id=DOWNLINK_PDR_CTR_IDX,
        )

        # Add rules for sending/receiving packets to/from dbuf
        # (sending isn't done by this test though)
        self.add_dbuf_device(
            dbuf_addr=DBUF_IPV4,
            drain_dst_addr=DBUF_DRAIN_DST_IPV4,
            dbuf_far_id=DBUF_FAR_ID,
            dbuf_teid=DBUF_TEID,
        )

        # Clear SPGW counters before sending the packet
        self.reset_pdr_counters(DOWNLINK_PDR_CTR_IDX)

        self.runIPv4UnicastTest(
            pkt=pkt_from_dbuf,
            dst_ipv4=exp_pkt[IP].dst,
            next_hop_mac=S1U_ENB_MAC,
            prefix_len=32,
            exp_pkt=exp_pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

        ingress_bytes = 0
        # Since the counter will use the packet length before the pipeline encaped with
        # GTPU headers, we need to remove it from the expected result.
        egress_bytes = (
            len(exp_pkt) + BMD_BYTES - IP_HDR_BYTES - UDP_HDR_BYTES - GTP_HDR_BYTES
        )
        if tagged1:
            egress_bytes += 4  # FIXME: why is this necessary?
        if not tagged2:
            egress_bytes += 4  # FIXME: why?
        if is_next_hop_spine:
            egress_bytes -= 4  # FIXME: ?????
        if self.loopback:
            egress_bytes += CPU_LOOPBACK_FAKE_ETHERNET_LENGTH

        # Verify the Ingress PDR packet counter did not increase, but the
        # egress did
        self.verify_pdr_counters(
            DOWNLINK_PDR_CTR_IDX, ingress_bytes, egress_bytes, 0, 1
        )


class SpgwReadWriteSymmetryTest(SpgwSimpleTest):
    """Verifies all SPGW tables adhere to p4runtime read-write symmetry.
    This is a temporary unit test, only meant to exist until a better test
    is written that programmatically verifies read-write symmetry test on
    all tables and actions found in the p4info.
    """

    def getActionFromReadEntry(self, table_entry):
        action = table_entry.action.action
        action_name = self.get_obj_name_from_id(action.action_id)

        p4info_params = self.get_obj("actions", action_name).params
        name_list = [""] * len(p4info_params)
        for param in p4info_params:
            name_list[param.id - 1] = param.name

        params = [
            (name_list[param.param_id - 1], param.value) for param in action.params
        ]
        return (action_name, params)

    def writeAndReadEntry(self, table_name, match_keys, action_name, action_params):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_action(
            req, table_name, match_keys, action_name, action_params
        )
        self.write_request(req)
        # 'read' here is past tense
        read_entry = self.read_table_entry(table_name, match_keys)
        if read_entry is None:
            self.fail(
                "Failed to read an entry that was just written! "
                + "Table was %s, action was %s" % (table_name, action_name)
            )

        read_action_name, read_action_params = self.getActionFromReadEntry(read_entry)
        if not read_action_name.endswith(action_name):
            self.fail(
                "Read action name does end with written action name"
                + "\n>> Read action name: %s" % read_action_name
                + "\n>> Written action name: %s" % action_name
            )

        if set(read_action_params) != set(action_params):
            self.fail(
                "Read action params do not equal written action params"
                + "\n>> Read params: %s" % str(read_action_params)
                + "\n>> Written params: %s" % str(action_params)
            )

    def checkInterfaceTable(
        self, iface_addr="1.1.1.1", prefix_len=32, gtpu_valid=1, iface_enum=1
    ):
        match_keys = [
            self.Lpm("ipv4_dst_addr", ipv4_to_binary(iface_addr), prefix_len),
            self.Exact("gtpu_is_valid", stringify(int(gtpu_valid), 1)),
        ]
        action_params = [("src_iface", stringify(iface_enum, 1))]
        self.writeAndReadEntry(
            "FabricIngress.spgw.interfaces",
            match_keys,
            "FabricIngress.spgw.load_iface",
            action_params,
        )

    def checkUplinkPdrTable(
        self, teid=1, tunnel_dst_addr="1.1.1.1", ctr_id=1, far_id=1, decap_flag=1,
    ):
        match_keys = [
            self.Exact("teid", stringify(teid, 4)),
            self.Exact("tunnel_ipv4_dst", ipv4_to_binary(tunnel_dst_addr)),
        ]
        action_params = [
            ("ctr_id", stringify(ctr_id, 2)),
            ("far_id", stringify(far_id, 4)),
            ("needs_gtpu_decap", stringify(decap_flag, 1)),
        ]
        self.writeAndReadEntry(
            "FabricIngress.spgw.uplink_pdrs",
            match_keys,
            "FabricIngress.spgw.load_pdr",
            action_params,
        )

    def checkDownlinkPdrTable(
        self, ue_addr="1.1.1.1", ctr_id=1, far_id=1, decap_flag=1
    ):
        match_keys = [self.Exact("ue_addr", ipv4_to_binary(ue_addr))]
        action_params = [
            ("ctr_id", stringify(ctr_id, 2)),
            ("far_id", stringify(far_id, 4)),
            ("needs_gtpu_decap", stringify(decap_flag, 1)),
        ]
        self.writeAndReadEntry(
            "FabricIngress.spgw.downlink_pdrs",
            match_keys,
            "FabricIngress.spgw.load_pdr",
            action_params,
        )

    def checkNormalFar(self, far_id=509, drop_flag=1, notify_flag=1):
        match_keys = [self.Exact("far_id", stringify(far_id, 4))]
        action_params = [
            ("drop", stringify(drop_flag, 1)),
            ("notify_cp", stringify(notify_flag, 1)),
        ]
        self.writeAndReadEntry(
            "FabricIngress.spgw.fars",
            match_keys,
            "FabricIngress.spgw.load_normal_far",
            action_params,
        )

    def checkTunnelFar(
        self,
        far_id=510,
        drop_flag=1,
        notify_flag=1,
        teid=56789,
        tunnel_src_port=1234,
        tunnel_src_addr="1.1.1.1",
        tunnel_dst_addr="2.2.2.2",
    ):
        match_keys = [self.Exact("far_id", stringify(far_id, 4))]
        action_params = [
            ("drop", stringify(drop_flag, 1)),
            ("notify_cp", stringify(notify_flag, 1)),
            ("teid", stringify(teid, 4)),
            ("tunnel_src_port", stringify(tunnel_src_port, 2)),
            ("tunnel_src_addr", ipv4_to_binary(tunnel_src_addr)),
            ("tunnel_dst_addr", ipv4_to_binary(tunnel_dst_addr)),
        ]
        self.writeAndReadEntry(
            "FabricIngress.spgw.fars",
            match_keys,
            "FabricIngress.spgw.load_tunnel_far",
            action_params,
        )

    def checkDbufFar(
        self,
        far_id=511,
        drop_flag=1,
        notify_flag=1,
        teid=56789,
        tunnel_src_port=1234,
        tunnel_src_addr="1.1.1.1",
        tunnel_dst_addr="2.2.2.2",
    ):
        match_keys = [self.Exact("far_id", stringify(far_id, 4))]
        action_params = [
            ("drop", stringify(drop_flag, 1)),
            ("notify_cp", stringify(notify_flag, 1)),
            ("teid", stringify(teid, 4)),
            ("tunnel_src_port", stringify(tunnel_src_port, 2)),
            ("tunnel_src_addr", ipv4_to_binary(tunnel_src_addr)),
            ("tunnel_dst_addr", ipv4_to_binary(tunnel_dst_addr)),
        ]
        self.writeAndReadEntry(
            "FabricIngress.spgw.fars",
            match_keys,
            "FabricIngress.spgw.load_dbuf_far",
            action_params,
        )

    def runReadWriteSymmetryTest(self):
        self.checkInterfaceTable()
        self.checkUplinkPdrTable()
        self.checkDownlinkPdrTable()
        self.checkNormalFar()
        self.checkTunnelFar()
        self.checkDbufFar()


class ConquestTest(IPv4UnicastTest):
    CONQ_REPORT_MIRROR_IDS = [400, 401, 402, 403]


    def set_up_report_mirrors(self, pipe_id, mirror_id, port):
        for mirror_id in CONQ_REPORT_MIRROR_IDS:
            self.add_clone_group(mirror_id, [self.cpu_port])


    def set_up_report_trigger(self):

        table_name = "tb_per_flow_action"
        action = "trigger_report"

        match_keys = [
                        self.Range("snap_0",        0,  2**16),
                        self.Range("q_delay",       0,  2**18),
                        self.Range("random_bits",   0,  2**8),
                        self.Exact("ecn",           0,  2**2),
                    ]
        action_params = []

        self.send_request_add_entry_to_action(
                table_name,
                match_keys,
                action,
                action_params)


    def runReportTriggerTest(self, pkt, tagged1, tagged2, is_next_hop_spine):
        set_up_report_trigger()
        set_up_report_mirrors()

        dst_mac = HOST2_MAC

        exp_pkt = pkt.copy()
        exp_pkt[Ether].src = pkt[Ether].dst
        exp_pkt[Ether].dst = dst_mac
        if not is_next_hop_spine:
            exp_pkt[IP].ttl = exp_pkt[IP].ttl - 1
        else:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)

        self.runIPv4UnicastTest(
            pkt=pkt,
            dst_ipv4=pkt[IP].dst,
            next_hop_mac=dst_mac,
            prefix_len=32,
            exp_pkt=exp_pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
        )

        # try to get any packet-in message
        self.get_packet_in()
        # TODO: parse the packet-in and verify the conquest report header



class IntTest(IPv4UnicastTest):
    """
    This test includes two parts:
    1. Reusing IPv4 unicast routing test to install routing entries,
       emitting the packet, and check the expected routed packet.
    2. Installs INT related table entries and create an expected INT report
       packet to verify the output.
    """

    def set_up_report_flow(
        self, port, src_mac, mon_mac, src_ip, mon_ip, mon_port, mon_label=None
    ):
        action = "do_report_encap"
        action_params = [
            ("src_mac", mac_to_binary(src_mac)),
            ("mon_mac", mac_to_binary(mon_mac)),
            ("src_ip", ipv4_to_binary(src_ip)),
            ("mon_ip", ipv4_to_binary(mon_ip)),
            ("mon_port", stringify(mon_port, 2)),
        ]
        if mon_label:
            action = "do_report_encap_mpls"
            action_params.append(("mon_label", stringify(mon_label, 3)))

        self.send_request_add_entry_to_action(
            "report",
            [
                self.Exact("bmd_type", stringify(BRIDGED_MD_TYPE_EGRESS_MIRROR, 1)),
                self.Exact("mirror_type", stringify(MIRROR_TYPE_INT_REPORT, 1)),
                self.Exact("int_report_type", stringify(INT_REPORT_TYPE_LOCAL, 1)),
            ],
            action,
            action_params,
        )

    def set_up_report_mirror_flow(self, pipe_id, mirror_id, port):
        self.add_clone_group(mirror_id, [port])
        # TODO: We plan to set up this table by using the control
        # plane so we don't need to hard code the session id
        # in pipeline.
        # self.send_request_add_entry_to_action(
        #     "tb_set_mirror_session_id",
        #     [self.Exact("pipe_id", stringify(pipe_id, 1))],
        #     "set_mirror_session_id", [
        #         ("sid", stringify(mirror_id, 2))
        #     ])

    def set_up_flow_report_filter_config(self, hop_latency_mask, timestamp_mask):
        self.send_request_add_entry_to_action(
            "FabricEgress.int_egress.flow_report_filter.config",
            [],
            "FabricEgress.int_egress.flow_report_filter.set_config",
            [
                ("hop_latency_mask", stringify(hop_latency_mask, 4)),
                ("timestamp_mask", stringify(timestamp_mask, 6)),
            ],
        )

    def set_up_watchlist_flow(self, ipv4_src, ipv4_dst, sport, dport):
        ipv4_src_ = ipv4_to_binary(ipv4_src)
        ipv4_dst_ = ipv4_to_binary(ipv4_dst)
        ipv4_mask = ipv4_to_binary("255.255.255.255")
        # Use full range of TCP/UDP ports by default.
        sport_low = stringify(0, 2)
        sport_high = stringify(0xFFFF, 2)
        dport_low = stringify(0, 2)
        dport_high = stringify(0xFFFF, 2)

        if sport:
            sport_low = stringify(sport, 2)
            sport_high = stringify(sport, 2)

        if dport:
            dport_low = stringify(dport, 2)
            dport_high = stringify(dport, 2)

        self.send_request_add_entry_to_action(
            "watchlist",
            [
                self.Ternary("ipv4_src", ipv4_src_, ipv4_mask),
                self.Ternary("ipv4_dst", ipv4_dst_, ipv4_mask),
                self.Range("l4_sport", sport_low, sport_high),
                self.Range("l4_dport", dport_low, dport_high),
            ],
            "mark_to_report",
            [],
            priority=DEFAULT_PRIORITY,
        )

    def set_up_int_mirror_flow(self, switch_id, report_type=INT_REPORT_TYPE_LOCAL):
        switch_id_ = stringify(switch_id, 4)
        report_type_ = stringify(report_type, 1)
        self.send_request_add_entry_to_action(
            "int_metadata",
            [self.Exact("int_report_type", report_type_),],
            "set_metadata",
            [("switch_id", switch_id_)],
        )

    def build_int_local_report(
        self,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        ig_port,
        eg_port,
        sw_id,
        inner_packet,
        is_device_spine,
        send_report_to_spine,
    ):
        # Note: scapy doesn't support dscp field, use tos.
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=64, tos=4)
            / UDP(sport=0, chksum=0)
            / INT_L45_REPORT_FIXED(nproto=2, f=1, hw_id=0)
            / INT_L45_LOCAL_REPORT(
                switch_id=sw_id, ingress_port_id=ig_port, egress_port_id=eg_port,
            )
            / inner_packet
        )
        if send_report_to_spine:
            mpls_ttl = DEFAULT_MPLS_TTL
            if is_device_spine:
                # MPLS label swap
                mpls_ttl -= 1
            pkt = pkt_add_mpls(pkt, label=MPLS_LABEL_2, ttl=mpls_ttl)
        else:
            pkt_decrement_ttl(pkt)

        mask_pkt = Mask(pkt)
        # IPv4 identifcation
        mask_pkt.set_do_not_care_scapy(IP, "id")
        # The reason we also ignore IP checksum is because the `id` field is
        # random.
        mask_pkt.set_do_not_care_scapy(IP, "chksum")
        mask_pkt.set_do_not_care_scapy(UDP, "chksum")
        mask_pkt.set_do_not_care_scapy(INT_L45_REPORT_FIXED, "ingress_tstamp")
        mask_pkt.set_do_not_care_scapy(INT_L45_REPORT_FIXED, "seq_no")
        mask_pkt.set_do_not_care_scapy(INT_L45_LOCAL_REPORT, "queue_id")
        mask_pkt.set_do_not_care_scapy(INT_L45_LOCAL_REPORT, "queue_occupancy")
        mask_pkt.set_do_not_care_scapy(INT_L45_LOCAL_REPORT, "egress_tstamp")

        return mask_pkt

    def set_up_report_table_entries(
        self, collector_port, is_device_spine, send_report_to_spine
    ):
        self.setup_port(collector_port, DEFAULT_VLAN)
        # Here we use next-id 101 since `runIPv4UnicastTest` will use 100 by
        # default
        next_id = 101
        prefix_len = 32
        group_id = next_id
        if is_device_spine:
            self.add_forwarding_mpls_entry(MPLS_LABEL_1, next_id)
            if send_report_to_spine:
                # Spine to spine
                params = [
                    collector_port,
                    SWITCH_MAC,
                    INT_COLLECTOR_MAC,
                    MPLS_LABEL_2,
                ]
                self.add_next_mpls_routing_group(next_id, group_id, [params])
            else:
                # Spine to leaf
                self.add_next_routing(
                    next_id, collector_port, SWITCH_MAC, INT_COLLECTOR_MAC
                )
        else:
            self.add_forwarding_routing_v4_entry(
                INT_COLLECTOR_IPV4, prefix_len, next_id
            )
            if send_report_to_spine:
                # Leaf to spine
                params = [
                    collector_port,
                    SWITCH_MAC,
                    INT_COLLECTOR_MAC,
                    MPLS_LABEL_2,
                ]
                self.add_next_mpls_routing_group(next_id, group_id, [params])
            else:
                # Leaf to host
                self.add_next_routing(
                    next_id, collector_port, SWITCH_MAC, INT_COLLECTOR_MAC
                )
        self.add_next_vlan(next_id, DEFAULT_VLAN)

    def build_inner_int_packet(self, pkt, is_next_hop_spine, tagged2):
        int_inner_pkt = pkt.copy()
        int_inner_pkt = pkt_route(int_inner_pkt, HOST2_MAC)
        if not is_next_hop_spine:
            int_inner_pkt = pkt_decrement_ttl(int_inner_pkt)
        if tagged2 and Dot1Q not in int_inner_pkt:
            int_inner_pkt = pkt_add_vlan(int_inner_pkt, vlan_vid=VLAN_ID_2)
        # Note that we won't add MPLS header to the expected inner
        # packet since the pipeline will strip out the MPLS header
        # from it before in the parser.
        return int_inner_pkt

    def set_up_int_flows(self, is_device_spine, pkt, send_report_to_spine):
        if UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        else:
            sport = None
            dport = None
        self.set_up_watchlist_flow(pkt[IP].src, pkt[IP].dst, sport, dport)
        self.set_up_int_mirror_flow(1)
        self.set_up_report_flow(
            self.port3,
            SWITCH_MAC,
            SWITCH_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            INT_REPORT_PORT,
            MPLS_LABEL_1 if is_device_spine else None,
        )
        for i in range(0, 4):
            self.set_up_report_mirror_flow(
                i, INT_REPORT_MIRROR_IDS[i], RECIRCULATE_PORTS[i]
            )

        # Set up entries for report packet
        self.set_up_report_table_entries(
            self.port3, is_device_spine, send_report_to_spine
        )

    def runIntTest(
        self,
        pkt,
        tagged1,
        tagged2,
        is_next_hop_spine,
        ig_port,
        eg_port,
        expect_int_report,
        is_device_spine,
        send_report_to_spine,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param prefix_len: prefix length to use in the routing table
        :param is_next_hop_spine: whether the packet should be routed
               to the spines using MPLS SR
        :param ig_port: the ingress port of the IP uncast packet
        :param eg_port: the egress port of the IP uncast packet
        :param expect_int_report: expected to receive the INT report
        :param is_device_spine: the device is a spine device
        :param send_report_to_spine: if the report is to be forwarded
               to a spine (e.g., collector attached to another leaf)
        """
        # Build expected inner pkt using the input one.
        int_inner_pkt = self.build_inner_int_packet(pkt, is_next_hop_spine, tagged2)

        # The expected INT report packet
        exp_int_report_pkt_masked = self.build_int_local_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            ig_port,
            eg_port,
            SWITCH_ID,
            int_inner_pkt,
            is_device_spine,
            send_report_to_spine,
        )

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
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
        )

        if expect_int_report:
            self.verify_packet(exp_int_report_pkt_masked, self.port3)
        self.verify_no_other_packets()


class SpgwIntTest(SpgwSimpleTest, IntTest):
    """
    This test includes two parts:
    1. Spgw uplink and downlink test which installs entries to route, encap,
       and decap GTP traffic. The test will also emit the packet and check the
       expected packet.
    2. Installs INT related table entries and check the expected report packet.
       Note that the expected packet in the INT report should be the packet
       without GTPU headers(IP/UDP/GTPU).
    """

    def runSpgwUplinkIntTest(
        self,
        pkt,
        tagged1,
        tagged2,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param is_next_hop_spine: whether the packet should be routed
               to the spines using MPLS SR
        :param is_device_spine: the device is a spine device
        :param send_report_to_spine: if the report is to be forwarded
               to a spine (e.g., collector attached to another leaf)
        """
        # Build packet from eNB
        # Add GTPU header to the original packet
        gtp_pkt = pkt_add_gtp(
            pkt, out_ipv4_src=S1U_ENB_IPV4, out_ipv4_dst=S1U_SGW_IPV4, teid=UPLINK_TEID,
        )

        # We should expected to receive an routed packet with no GTPU headers.
        # Build exp pkt using the input one.
        int_inner_pkt = self.build_inner_int_packet(pkt, is_next_hop_spine, tagged2)

        exp_output_pkt_from_device = int_inner_pkt
        if is_next_hop_spine:
            # Note that we won't add MPLS header to the expected inner
            # packet since the pipeline will strip out the MPLS header
            # from it before in the parser.
            # This is the packet we expected to be received by the
            # upstream
            exp_output_pkt_from_device = pkt_add_mpls(
                int_inner_pkt, label=MPLS_LABEL_2, ttl=DEFAULT_MPLS_TTL
            )

        # We should also expected an INT report packet
        exp_int_report_pkt_masked = self.build_int_local_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            self.port1,
            self.port2,
            SWITCH_ID,
            int_inner_pkt,
            is_device_spine,
            send_report_to_spine,
        )

        # Set up entries for uplink
        self.setup_uplink(
            s1u_sgw_addr=S1U_SGW_IPV4, teid=UPLINK_TEID, ctr_id=UPLINK_PDR_CTR_IDX,
        )

        # Set collector, report table, and mirror sessions
        # Note that we are monitoring the inner packet.
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        self.runIPv4UnicastTest(
            pkt=gtp_pkt,
            dst_ipv4=pkt[IP].dst,
            exp_pkt=exp_output_pkt_from_device,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            with_another_pkt_later=True,
        )

        self.verify_packet(exp_int_report_pkt_masked, self.port3)
        self.verify_no_other_packets()

    def runSpgwDownlinkIntTest(
        self,
        pkt,
        tagged1,
        tagged2,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param is_next_hop_spine: whether the packet should be routed
               to the spines using MPLS SR
        :param is_device_spine: the device is a spine device
        :param send_report_to_spine: if the report is to be forwarded
               to a spine (e.g., collector attached to another leaf)
        """
        # We should expected to receive an packet with GTPU headers.
        exp_pkt = pkt.copy()
        int_inner_pkt = self.build_inner_int_packet(pkt, is_next_hop_spine, tagged2)
        if not is_next_hop_spine:
            exp_pkt = pkt_decrement_ttl(exp_pkt)
        exp_pkt = pkt_add_gtp(
            exp_pkt,
            out_ipv4_src=S1U_SGW_IPV4,
            out_ipv4_dst=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
        )
        exp_pkt = pkt_route(exp_pkt, HOST2_MAC)
        if tagged2 and Dot1Q not in exp_pkt:
            exp_pkt = pkt_add_vlan(exp_pkt, vlan_vid=VLAN_ID_2)
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, label=MPLS_LABEL_2, ttl=DEFAULT_MPLS_TTL)
            # Note that we won't add MPLS header to the expected inner
            # packet since the pipeline will strip out the MPLS header
            # from it in the parser.

        # We should also expected an INT report packet
        exp_int_report_pkt_masked = self.build_int_local_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            self.port1,
            self.port2,
            SWITCH_ID,
            int_inner_pkt,
            is_device_spine,
            send_report_to_spine,
        )

        # Set up entries for downlink
        self.setup_downlink(
            s1u_sgw_addr=S1U_SGW_IPV4,
            s1u_enb_addr=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
            ue_addr=pkt[IP].dst,
            ctr_id=DOWNLINK_PDR_CTR_IDX,
        )

        # Set collector, report table, and mirror sessions
        # Note that we are monitoring the inner packet.
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        self.runIPv4UnicastTest(
            pkt=pkt,
            dst_ipv4=S1U_ENB_IPV4,
            next_hop_mac=HOST2_MAC,
            prefix_len=32,
            exp_pkt=exp_pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            with_another_pkt_later=True,
        )

        self.verify_packet(exp_int_report_pkt_masked, self.port3)
        self.verify_no_other_packets()


class PppoeTest(DoubleVlanTerminationTest):
    def set_line_map(self, s_tag, c_tag, line_id):
        assert line_id != 0
        s_tag_ = stringify(s_tag, 2)  # outer
        c_tag_ = stringify(c_tag, 2)  # inner
        line_id_ = stringify(line_id, 4)

        # Upstream
        self.send_request_add_entry_to_action(
            "bng_ingress.t_line_map",
            [self.Exact("s_tag", s_tag_), self.Exact("c_tag", c_tag_)],
            "bng_ingress.set_line",
            [("line_id", line_id_)],
        )

    def setup_line_v4(
        self, s_tag, c_tag, line_id, ipv4_addr, mac_src, pppoe_session_id, enabled=True,
    ):
        assert s_tag != 0
        assert c_tag != 0
        assert line_id != 0
        assert pppoe_session_id != 0

        line_id_ = stringify(line_id, 4)
        ipv4_addr_ = ipv4_to_binary(ipv4_addr)
        pppoe_session_id_ = stringify(pppoe_session_id, 2)

        # line map common to up and downstream
        self.set_line_map(s_tag=s_tag, c_tag=c_tag, line_id=line_id)
        # Upstream
        if enabled:
            # Enable upstream termination.
            self.send_request_add_entry_to_action(
                "bng_ingress.upstream.t_pppoe_term_v4",
                [
                    self.Exact("line_id", line_id_),
                    # self.Exact("eth_src", mac_src_),
                    self.Exact("ipv4_src", ipv4_addr_),
                    self.Exact("pppoe_session_id", pppoe_session_id_),
                ],
                "bng_ingress.upstream.term_enabled_v4",
                [],
            )

        # Downstream
        if enabled:
            a_name = "set_session"
            a_params = [
                ("pppoe_session_id", pppoe_session_id_),
            ]
        else:
            a_name = "drop"
            a_params = []
        self.send_request_add_entry_to_action(
            "bng_ingress.downstream.t_line_session_map",
            [self.Exact("line_id", line_id_)],
            "bng_ingress.downstream." + a_name,
            a_params,
        )

    def set_upstream_pppoe_cp_table(self, pppoe_codes=()):
        for code in pppoe_codes:
            code_ = stringify(code, 1)
            self.send_request_add_entry_to_action(
                "bng_ingress.upstream.t_pppoe_cp",
                [self.Exact("pppoe_code", code_)],
                "bng_ingress.upstream.punt_to_cpu",
                [],
                DEFAULT_PRIORITY,
            )

    def setup_bng(self, pppoe_cp_codes=PPPOED_CODES):
        self.set_upstream_pppoe_cp_table(pppoe_codes=pppoe_cp_codes)

    def read_pkt_count(self, c_name, line_id):
        counter = self.read_indirect_counter(c_name, line_id, typ="PACKETS")
        return counter.data.packet_count

    def read_byte_count(self, c_name, line_id):
        counter = self.read_indirect_counter(c_name, line_id, typ="BYTES")
        return counter.data.byte_count

    def read_pkt_count_upstream(self, type, line_id):
        return self.read_pkt_count("bng_ingress.upstream.c_" + type, line_id)

    def read_byte_count_upstream(self, type, line_id):
        return self.read_byte_count("bng_ingress.upstream.c_" + type, line_id)

    def read_byte_count_downstream_rx(self, line_id):
        return self.read_byte_count("bng_ingress.downstream.c_line_rx", line_id)

    def read_byte_count_downstream_tx(self, line_id):
        return self.read_byte_count("bng_egress.downstream.c_line_tx", line_id)

    def runUpstreamV4Test(self, pkt, tagged2, is_next_hop_spine, line_enabled=True):
        s_tag = vlan_id_outer = 888
        c_tag = vlan_id_inner = 777
        line_id = 99
        pppoe_session_id = 0xBEAC
        core_router_mac = HOST1_MAC

        self.setup_bng()
        self.setup_line_v4(
            s_tag=s_tag,
            c_tag=c_tag,
            line_id=line_id,
            ipv4_addr=pkt[IP].src,
            mac_src=pkt[Ether].src,
            pppoe_session_id=pppoe_session_id,
            enabled=line_enabled,
        )

        # Input is the given packet with double VLAN tags and PPPoE headers.
        pppoe_pkt = pkt_add_pppoe(
            pkt, type=1, code=PPPOE_CODE_SESSION_STAGE, session_id=pppoe_session_id,
        )
        pppoe_pkt = pkt_add_vlan(pppoe_pkt, vlan_vid=vlan_id_inner)
        pppoe_pkt = pkt_add_vlan(pppoe_pkt, vlan_vid=vlan_id_outer)

        # Build expected packet from the input one, we expect it to be routed
        # as if it was without VLAN tags and PPPoE headers.
        exp_pkt = pkt.copy()
        exp_pkt = pkt_route(exp_pkt, core_router_mac)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_3)
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        else:
            exp_pkt = pkt_decrement_ttl(exp_pkt)

        # Read counters, will verify their values later.
        old_terminated = self.read_byte_count_upstream("terminated", line_id)
        old_dropped = self.read_byte_count_upstream("dropped", line_id)

        old_control = self.read_pkt_count_upstream("control", line_id)

        self.runPopAndRouteTest(
            pkt=pppoe_pkt,
            next_hop_mac=core_router_mac,
            exp_pkt=exp_pkt,
            out_tagged=tagged2,
            vlan_id=s_tag,
            inner_vlan_id=c_tag,
            verify_pkt=line_enabled,
            is_next_hop_spine=is_next_hop_spine,
        )

        # Verify that upstream counters were updated as expected.
        if not self.is_bmv2():
            time.sleep(1)
        new_terminated = self.read_byte_count_upstream("terminated", line_id)
        new_dropped = self.read_byte_count_upstream("dropped", line_id)

        new_control = self.read_pkt_count_upstream("control", line_id)

        # No control plane packets here.
        self.assertEqual(new_control, old_control)

        # Using assertGreaterEqual because some targets may or may not count
        # FCS
        if line_enabled:
            self.assertGreaterEqual(new_terminated, old_terminated + len(pppoe_pkt))
            self.assertEqual(new_dropped, old_dropped)
        else:
            self.assertEqual(new_terminated, old_terminated)
            self.assertGreaterEqual(new_dropped, old_dropped + len(pppoe_pkt))

    def runControlPacketInTest(self, pppoed_pkt, line_mapped=True):
        s_tag = vlan_id_outer = 888
        c_tag = vlan_id_inner = 777

        self.setup_bng()
        # If a line mapping is not provided, we expect packets to be processed
        # with line ID 0 (e.g. counters updated at index 0).
        line_id = 0
        if line_mapped:
            line_id = 99
            self.set_line_map(s_tag=s_tag, c_tag=c_tag, line_id=line_id)

        pppoed_pkt = pkt_add_vlan(pppoed_pkt, vlan_vid=vlan_id_outer)
        pppoed_pkt = pkt_add_inner_vlan(pppoed_pkt, vlan_vid=vlan_id_inner)

        old_terminated = self.read_byte_count_upstream("terminated", line_id)
        old_dropped = self.read_byte_count_upstream("dropped", line_id)
        old_control = self.read_pkt_count_upstream("control", line_id)

        self.send_packet(self.port1, pppoed_pkt)
        self.verify_packet_in(pppoed_pkt, self.port1)
        self.verify_no_other_packets()

        if not self.is_bmv2():
            time.sleep(1)
        new_terminated = self.read_byte_count_upstream("terminated", line_id)
        new_dropped = self.read_byte_count_upstream("dropped", line_id)

        new_control = self.read_pkt_count_upstream("control", line_id)

        # Only control plane packets.
        self.assertEqual(new_terminated, old_terminated)
        self.assertEqual(new_dropped, old_dropped)
        self.assertEqual(new_control, old_control + 1)

    def runControlPacketOutTest(self, pppoed_pkt):
        vlan_id_outer = 888
        vlan_id_inner = 777

        self.setup_bng()

        # Assuming pkts are double-tagged at the control plane.
        pppoed_pkt = pkt_add_vlan(pppoed_pkt, vlan_vid=vlan_id_inner)
        pppoed_pkt = pkt_add_vlan(pppoed_pkt, vlan_vid=vlan_id_outer)

        self.verify_packet_out(pppoed_pkt, self.port1)
        self.verify_no_other_packets()

    def runDownstreamV4Test(self, pkt, in_tagged, line_enabled):
        s_tag = vlan_id_outer = 888
        c_tag = vlan_id_inner = 777
        line_id = 99
        next_id = 99
        pppoe_session_id = 0xBEAC
        olt_mac = HOST1_MAC

        self.setup_bng()
        self.setup_line_v4(
            s_tag=s_tag,
            c_tag=c_tag,
            line_id=line_id,
            ipv4_addr=pkt[IP].dst,
            mac_src=pkt[Ether].src,
            pppoe_session_id=pppoe_session_id,
            enabled=line_enabled,
        )

        # Build expected packet from the input one, we expect it to be routed
        # and encapsulated in double VLAN tags and PPPoE.
        exp_pkt = pkt_add_pppoe(
            pkt, type=1, code=PPPOE_CODE_SESSION_STAGE, session_id=pppoe_session_id,
        )
        exp_pkt = pkt_add_vlan(exp_pkt, vlan_vid=vlan_id_outer)
        exp_pkt = pkt_add_inner_vlan(exp_pkt, vlan_vid=vlan_id_inner)
        exp_pkt = pkt_route(exp_pkt, olt_mac)
        exp_pkt = pkt_decrement_ttl(exp_pkt)

        old_rx_count = self.read_byte_count_downstream_rx(line_id)
        old_tx_count = self.read_byte_count_downstream_tx(line_id)

        self.runRouteAndPushTest(
            pkt=pkt,
            next_hop_mac=olt_mac,
            exp_pkt=exp_pkt,
            in_tagged=in_tagged,
            next_id=next_id,
            next_vlan_id=s_tag,
            next_inner_vlan_id=c_tag,
            verify_pkt=line_enabled,
        )

        if not self.is_bmv2():
            time.sleep(1)
        new_rx_count = self.read_byte_count_downstream_rx(line_id)
        new_tx_count = self.read_byte_count_downstream_tx(line_id)

        # Using assertGreaterEqual because some targets may or may not count
        # FCS
        self.assertGreaterEqual(new_rx_count, old_rx_count + len(pkt))
        if line_enabled:
            self.assertGreaterEqual(new_tx_count, old_tx_count + len(pkt))
        else:
            self.assertEqual(new_tx_count, old_tx_count)
