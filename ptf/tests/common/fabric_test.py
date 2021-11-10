# Copyright 2013-2018 Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

import codecs
import fnmatch
import re
import socket
import struct
import time

import xnt
from base_test import (
    P4RuntimeTest,
    ipv4_to_binary,
    is_bmv2,
    mac_to_binary,
    stringify,
    tvcreate,
)
from bmd_bytes import BMD_BYTES
from p4.v1 import p4runtime_pb2
from ptf import testutils
from ptf.mask import Mask
from qos_utils import QUEUE_ID_SYSTEM
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.ppp import PPP, PPPoE
from scapy.layers.sctp import SCTP
from scapy.layers.vxlan import VXLAN
from scapy.packet import bind_layers

vlan_confs = {
    "tag->tag": [True, True],
    "untag->untag": [False, False],
    "tag->untag": [True, False],
    "untag->tag": [False, True],
}

BASE_PKT_TYPES = {"tcp", "udp", "icmp", "sctp"}
GTP_PKT_TYPES = {
    "gtp_tcp",
    "gtp_udp",
    "gtp_icmp",
    "gtp_psc_ul_udp",
    "gtp_psc_dl_udp",
    "gtp_psc_ul_tcp",
    "gtp_psc_dl_tcp",
    "gtp_psc_dl_icmp",
    "gtp_psc_ul_icmp",
}
VXLAN_PKT_TYPES = {
    "vxlan_tcp",
    "vxlan_udp",
}

DEFAULT_PRIORITY = 10

FORWARDING_TYPE_BRIDGING = 0
FORWARDING_TYPE_MPLS = 1
FORWARDING_TYPE_UNICAST_IPV4 = 2
FORWARDING_TYPE_IPV4_MULTICAST = 3
FORWARDING_TYPE_IPV6_UNICAST = 4
FORWARDING_TYPE_IPV6_MULTICAST = 5
FORWARDING_TYPE_UNKNOWN = 7

DEFAULT_MPLS_TTL = 64
MIN_PKT_LEN = 80

UDP_GTP_PORT = 2152
DEFAULT_GTP_TUNNEL_SPORT = 1234  # arbitrary, but different from 2152
GTPU_EXT_PSC_TYPE_DL = 0
GTPU_EXT_PSC_TYPE_UL = 1

ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_QINQ = 0x88A8
ETH_TYPE_PPPOE = 0x8864
ETH_TYPE_MPLS_UNICAST = 0x8847

IP_PROTO_UDP = 0x11
IP_PROTO_TCP = 0x06
IP_PROTO_ICMP = 0x01
IP_PROTO_SCTP = 0x84

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
INT_L45_DROP_REPORT = xnt.INT_L45_DROP_REPORT

BROADCAST_MAC = ":".join(["ff"] * 6)
MAC_MASK = ":".join(["ff"] * 6)
MCAST_MAC = "01:00:5e:00:00:00"
MCAST_MASK = "ff:ff:ff:80:00:00"
SWITCH_MAC = "00:00:00:00:aa:01"
SWITCH_IPV4 = "192.168.0.1"
SPINE_MAC = "00:00:00:00:aa:02"

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
UE1_IPV4 = "16.255.255.1"
UE2_IPV4 = "16.255.255.2"
UE_SUBNET = "16.255.255.0"
UE_SUBNET_MASK = "255.255.255.0"

DEFAULT_ROUTE_IPV4 = "0.0.0.0"
PREFIX_DEFAULT_ROUTE = 0
PREFIX_SUBNET = 24
PREFIX_HOST = 32

DBUF_MAC = "00:00:00:0d:b0:0f"
DBUF_IPV4 = "141.0.0.1"
DBUF_DRAIN_DST_IPV4 = "142.0.0.1"
DBUF_FAR_ID = 1023
DBUF_TEID = 0

PDR_COUNTER_INGRESS = "FabricIngress.spgw.pdr_counter"
PDR_COUNTER_EGRESS = "FabricEgress.spgw.pdr_counter"

SPGW_IFACE_ACCESS = "iface_access"
SPGW_IFACE_CORE = "iface_core"
SPGW_IFACE_FROM_DBUF = "iface_dbuf"

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

PACKET_IN_MIRROR_ID = 0x1FF
INT_REPORT_MIRROR_IDS = [0x200, 0x201, 0x202, 0x203]
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
INT_TOS = 0

INT_REPORT_TYPE_NO_REPORT = 0
INT_REPORT_TYPE_DROP = 4
INT_REPORT_TYPE_QUEUE = 2
INT_REPORT_TYPE_FLOW = 1

INT_DROP_REASON_UNKNOWN = 0
INT_DROP_REASON_TRAFFIC_MANAGER = 71
INT_DROP_REASON_ACL_DENY = 80
INT_DROP_REASON_ROUTING_V4_MISS = 29
INT_DROP_REASON_EGRESS_NEXT_MISS = 130
INT_DROP_REASON_DOWNLINK_PDR_MISS = 132
INT_DROP_REASON_UPLINK_PDR_MISS = 133
INT_DROP_REASON_FAR_MISS = 134
INT_DEFAULT_QUEUE_REPORT_QUOTA = 1024
INT_MIRROR_TRUNCATE_MAX_LEN = 128
INT_MIRROR_BYTES = 27  # TODO: autogenerate it

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
MIRROR_TYPE_INVALID = 0
MIRROR_TYPE_INT_REPORT = 1

# Bridged metadata type
BRIDGED_MD_TYPE_EGRESS_MIRROR = 2
BRIDGED_MD_TYPE_INGRESS_MIRROR = 3
BRIDGED_MD_TYPE_INT_INGRESS_DROP = 4
BRIDGED_MD_TYPE_DEFLECTED = 5

IP_HDR_BYTES = 20
UDP_HDR_BYTES = 8
GTPU_HDR_BYTES = 8
VXLAN_HDR_BYTES = 8
GTPU_OPTIONS_HDR_BYTES = 4
GTPU_EXT_PSC_BYTES = 4
ETH_FCS_BYTES = 4
VLAN_BYTES = 4
CPU_LOOPBACK_FAKE_ETH_BYTES = 14

# Port types to be use with port_vlan table
PORT_TYPE_OTHER = b"\x00"
PORT_TYPE_EDGE = b"\x01"
PORT_TYPE_INFRA = b"\x02"
PORT_TYPE_INTERNAL = b"\x03"

DEFAULT_SLICE_ID = 0
DEFAULT_TC = 0
TC_WIDTH = 2  # bits

# High-level parameter specification options for get_test_args function
SPGW_OPTIONS = ["DL", "UL", "DL_PSC", "UL_PSC"]
INT_OPTIONS = ["local", "ig_drop", "eg_drop"]
SOURCE_OPTIONS = ["host", "leaf", "spine"]
DEVICE_OPTIONS = ["leaf", "spine"]
DEST_OPTIONS = ["host", "leaf", "spine"]

COLOR_GREEN = 0
COLOR_YELLOW = 1
BMV2_COLOR_RED = 2
COLOR_RED = 3

STATS_INGRESS = "Ingress"
STATS_EGRESS = "Egress"

STATS_TABLE = "Fabric%s.stats.flows"
STATS_ACTION = "Fabric%s.stats.count"

# Implements helper function for SCTP as PTF does not provide one.
def simple_sctp_packet(
    pktlen=100,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    dl_vlan_cfi=0,
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=0x0001,
    ip_flag=0,
    sctp_sport=1234,
    sctp_dport=80,
    ip_ihl=None,
    ip_options=False,
    with_sctp_chksum=True,
):
    """
    Return a simple dataplane SCTP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param sctp_dport SCTP destination port
    @param sctp_sport SCTP source port
    @param with_sctp_chksum Valid SCTP checksum

    Generates a simple SCTP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/SCTP frame.
    """

    if testutils.MINSIZE > pktlen:
        pktlen = testutils.MINSIZE

    if with_sctp_chksum:
        sctp_hdr = SCTP(sport=sctp_sport, dport=sctp_dport)
    else:
        sctp_hdr = SCTP(sport=sctp_sport, dport=sctp_dport, chksum=0)

    ip_tos = testutils.ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if dl_vlan_enable:
        pkt = (
            Ether(dst=eth_dst, src=eth_src)
            / Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
            / IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, id=ip_id)
            / sctp_hdr
        )
    else:
        if not ip_options:
            pkt = (
                Ether(dst=eth_dst, src=eth_src)
                / IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    ihl=ip_ihl,
                    id=ip_id,
                    flags=ip_flag,
                )
                / sctp_hdr
            )
        else:
            pkt = (
                Ether(dst=eth_dst, src=eth_src)
                / IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    ihl=ip_ihl,
                    options=ip_options,
                    id=ip_id,
                    flags=ip_flag,
                )
                / sctp_hdr
            )

    pkt = pkt / codecs.decode(
        "".join(["%02x" % (x % 256) for x in range(pktlen - len(pkt))]), "hex"
    )

    return pkt


# Generic function to generate a VXLAN-encapsulated pkt
# Default arg values are in line with PTF
def simple_vxlan_packet(
    pkt_type,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    pktlen=136,
):
    pktlen = pktlen - IP_HDR_BYTES - UDP_HDR_BYTES - VXLAN_HDR_BYTES
    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
        ip_src=ip_src, ip_dst=ip_dst, pktlen=pktlen
    )
    pkt = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=ip_src, dst=ip_dst)
        / UDP()
        / VXLAN()
        / pkt
    )
    return pkt


# Generic function to generate a GTP-encapsulated pkt
# Default arg values are in line with PTF
def simple_gtp_packet(
    pkt_type,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_ttl=64,
    gtp_teid=0xFF,  # dummy teid
    pktlen=136,
    ext_psc_type=None,
    ext_psc_qfi=0,
):
    pktlen = pktlen - IP_HDR_BYTES - UDP_HDR_BYTES - GTPU_HDR_BYTES
    if ext_psc_type is not None:
        pktlen = pktlen - GTPU_OPTIONS_HDR_BYTES - GTPU_EXT_PSC_BYTES
    pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
        ip_src=ip_src, ip_dst=ip_dst, pktlen=pktlen
    )
    gtp_pkt = pkt_add_gtp(
        pkt,
        out_ipv4_src=ip_src,
        out_ipv4_dst=ip_dst,
        teid=gtp_teid,
        ext_psc_type=ext_psc_type,
        ext_psc_qfi=ext_psc_qfi,
    )
    gtp_pkt[Ether].src = eth_src
    gtp_pkt[Ether].dst = eth_dst
    gtp_pkt[IP].ttl = ip_ttl
    return gtp_pkt


def simple_vxlan_tcp_packet(*args, **kwargs):
    return simple_vxlan_packet("tcp", *args, **kwargs)


def simple_vxlan_udp_packet(*args, **kwargs):
    return simple_vxlan_packet("udp", *args, **kwargs)


def simple_gtp_tcp_packet(*args, **kwargs):
    return simple_gtp_packet("tcp", *args, **kwargs)


def simple_gtp_udp_packet(*args, **kwargs):
    return simple_gtp_packet("udp", *args, **kwargs)


def simple_gtp_icmp_packet(*args, **kwargs):
    return simple_gtp_packet("icmp", *args, **kwargs)


def simple_gtp_psc_ul_tcp_packet(*args, **kwargs):
    return simple_gtp_packet("tcp", *args, ext_psc_type=GTPU_EXT_PSC_TYPE_UL, **kwargs)


def simple_gtp_psc_dl_tcp_packet(*args, **kwargs):
    return simple_gtp_packet("tcp", *args, ext_psc_type=GTPU_EXT_PSC_TYPE_DL, **kwargs)


def simple_gtp_psc_ul_udp_packet(*args, **kwargs):
    return simple_gtp_packet("udp", *args, ext_psc_type=GTPU_EXT_PSC_TYPE_UL, **kwargs)


def simple_gtp_psc_dl_udp_packet(*args, **kwargs):
    return simple_gtp_packet("udp", *args, ext_psc_type=GTPU_EXT_PSC_TYPE_DL, **kwargs)


def simple_gtp_psc_ul_icmp_packet(*args, **kwargs):
    return simple_gtp_packet("icmp", *args, ext_psc_type=GTPU_EXT_PSC_TYPE_UL, **kwargs)


def simple_gtp_psc_dl_icmp_packet(*args, **kwargs):
    return simple_gtp_packet("icmp", *args, ext_psc_type=GTPU_EXT_PSC_TYPE_DL, **kwargs)


# Embed the above functions in the testutils package.
setattr(testutils, "simple_sctp_packet", simple_sctp_packet)
setattr(testutils, "simple_gtp_tcp_packet", simple_gtp_tcp_packet)
setattr(testutils, "simple_gtp_udp_packet", simple_gtp_udp_packet)
setattr(testutils, "simple_gtp_icmp_packet", simple_gtp_icmp_packet)
setattr(testutils, "simple_gtp_psc_ul_tcp_packet", simple_gtp_psc_ul_tcp_packet)
setattr(testutils, "simple_gtp_psc_dl_tcp_packet", simple_gtp_psc_dl_tcp_packet)
setattr(testutils, "simple_gtp_psc_ul_udp_packet", simple_gtp_psc_ul_udp_packet)
setattr(testutils, "simple_gtp_psc_dl_udp_packet", simple_gtp_psc_dl_udp_packet)
setattr(testutils, "simple_gtp_psc_ul_icmp_packet", simple_gtp_psc_ul_icmp_packet)
setattr(testutils, "simple_gtp_psc_dl_icmp_packet", simple_gtp_psc_dl_icmp_packet)
setattr(testutils, "simple_vxlan_tcp_packet", simple_vxlan_tcp_packet)
setattr(testutils, "simple_vxlan_udp_packet", simple_vxlan_udp_packet)


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
    if Dot1Q in pkt:
        return (
            Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
            / Dot1Q(prio=pkt[Dot1Q].prio, id=pkt[Dot1Q].id, vlan=pkt[Dot1Q].vlan)
            / MPLS(label=label, cos=cos, s=s, ttl=ttl)
            / pkt[Dot1Q].payload
        )
    else:
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
    ext_psc_type=None,
    ext_psc_qfi=None,
):
    gtp_pkt = (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
        / IP(src=out_ipv4_src, dst=out_ipv4_dst, tos=0, id=0x1513, flags=0, frag=0,)
        / UDP(sport=sport, dport=dport, chksum=0)
        / GTP_U_Header(gtp_type=255, teid=teid)
    )
    if ext_psc_type is not None:
        # Add QoS Flow Identifier (QFI) as an extension header (required for 5G RAN)
        gtp_pkt = gtp_pkt / GTPPDUSessionContainer(type=ext_psc_type, QFI=ext_psc_qfi)
    return gtp_pkt / pkt[Ether].payload


def pkt_remove_gtp(pkt):
    if GTPPDUSessionContainer in pkt:
        payload = pkt[GTPPDUSessionContainer].payload
    elif GTP_U_Header in pkt:
        payload = pkt[GTP_U_Header].payload
    else:
        raise Exception("Not a GTP packet")
    return Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / payload


def pkt_remove_vxlan(pkt):
    assert VXLAN in pkt
    inner_pkt = pkt[VXLAN].payload
    inner_pkt[Ether].src = pkt[Ether].src
    inner_pkt[Ether].dst = pkt[Ether].dst
    return inner_pkt


def pkt_remove_vlan(pkt):
    assert Dot1Q in pkt
    payload = pkt[Dot1Q:1].payload
    return (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=pkt[Dot1Q:1].type) / payload
    )


def pkt_remove_mpls(pkt):
    assert MPLS in pkt
    payload = pkt[MPLS].payload
    if IP in payload:
        return (
            Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=ETH_TYPE_IPV4) / payload
        )


def pkt_decrement_ttl(pkt):
    if IP in pkt:
        pkt[IP].ttl -= 1
    return pkt


def get_test_args(
    traffic_dir,
    pkt_addrs={},
    spgw_type=None,
    int_test_type=None,
    test_multiple_pkt_len=False,
    test_multiple_prefix_len=False,
    ue_recirculation_test=False,
):

    """
    Generates parameters for doRunTest calls in test cases
    :param traffic_dir: traffic direction, e.g. "host-leaf-spine"
    :param pkt_addrs: packet header addresses, e.g. {eth_src, eth_dst, ip_src, ip_dst}
    :param spgw_type: SPGW direction, e.g. "DL" for downlink, "UL" for uplink
    :param int_test_type: INT test drop reason, e.g. "eg_drop" for egress drop type
    :param test_multiple_pkt_len: generate multiple packet lengths
    :param test_multiple_prefix_len: generate multiple prefix lengths
    :param ue_recirculation_test: allow UE recirculation (for recirculation tests)
    """

    drop_reason_list = []
    vlan_conf_list = []
    pkt_type_list = []
    with_psc_list = []
    send_report_to_spine_list = []
    pkt_len_list = []
    prefix_len_list = []
    allow_ue_recirculation_list = []

    # spgw input structure: "[DL/UL]_[optional: psc]"
    if spgw_type:
        spgw_specs = re.split("_", spgw_type)
        spgw_dir = spgw_specs[0]
        # if spgw_type includes psc
        try:
            psc_exist = spgw_specs[1]
            include_psc = True
        except IndexError:
            include_psc = False
    else:
        include_psc = False

    # traffic_dir input structure: "source-device-destination"
    devices = re.split("-", traffic_dir)
    if len(devices) != 3:
        raise Exception("Invalid traffic direction {}.".format(traffic_dir))
    source = devices[0]
    device = devices[1]
    dest = devices[2]

    if source not in SOURCE_OPTIONS:
        raise Exception("Invalid source specification: {}".format(source))
    if device not in DEVICE_OPTIONS:
        raise Exception("Invalid device specification: {}".format(device))
    if dest not in DEST_OPTIONS:
        raise Exception("Invalid dest specification: {}".format(dest))

    if source != "host" and dest != "host":
        vlan_conf_list = {"untag->untag": [False, False]}
    elif source == "host" and dest != "host":
        vlan_conf_list = {"tag->untag": [True, False], "untag->untag": [False, False]}
    elif source != "host" and dest == "host":
        vlan_conf_list = {"untag->tag": [False, True], "untag->untag": [False, False]}
    elif source == "host" and dest == "host":
        vlan_conf_list = {
            "untag->untag": [False, False],
            "untag->tag": [False, True],
            "tag->untag": [True, False],
            "tag->tag": [True, True],
        }
    else:
        raise Exception("Invalid source ({}) and/or dest ({})".format(source, dest))

    is_device_spine = device == "spine"
    is_next_hop_spine = dest == "spine"

    if int_test_type == "ig_drop":
        drop_reason_list = [INT_DROP_REASON_ACL_DENY]
    elif int_test_type == "eg_drop":
        if spgw_dir == "DL":
            drop_reason_list = [
                INT_DROP_REASON_DOWNLINK_PDR_MISS,
                INT_DROP_REASON_FAR_MISS,
            ]
        elif spgw_dir == "UL":
            drop_reason_list = [
                INT_DROP_REASON_UPLINK_PDR_MISS,
                INT_DROP_REASON_FAR_MISS,
            ]
        else:
            drop_reason_list = [INT_DROP_REASON_EGRESS_NEXT_MISS]
    else:
        drop_reason_list = [None]

    # Configure arrays for spgw-related tests
    # spgw only uses base packets and always considers psc
    if spgw_type in SPGW_OPTIONS:
        pkt_type_list = BASE_PKT_TYPES - {"sctp"}
        if include_psc:
            with_psc_list = [False, True]
        else:
            with_psc_list = [False]
    else:
        pkt_type_list = BASE_PKT_TYPES | GTP_PKT_TYPES | VXLAN_PKT_TYPES
        with_psc_list = [False]

    if int_test_type in INT_OPTIONS:
        send_report_to_spine_list = [False, True]
    else:
        send_report_to_spine_list = [None]

    if test_multiple_pkt_len:
        pkt_len_list = [MIN_PKT_LEN, 1500]
    else:
        pkt_len_list = [MIN_PKT_LEN]

    if test_multiple_prefix_len:
        prefix_len_list = [PREFIX_DEFAULT_ROUTE, PREFIX_SUBNET, PREFIX_HOST]
    else:
        prefix_len_list = [None]

    if ue_recirculation_test:
        if is_next_hop_spine:
            allow_ue_recirculation_list = [True]
        else:
            allow_ue_recirculation_list = [True, False]
    else:
        allow_ue_recirculation_list = [None]

    for drop_reason in drop_reason_list:
        for vlan_conf, tagged in vlan_conf_list.items():
            for pkt_type in pkt_type_list:
                for with_psc in with_psc_list:
                    for prefix_len in prefix_len_list:
                        for pkt_len in pkt_len_list:
                            for send_report_to_spine in send_report_to_spine_list:
                                for (
                                    allow_ue_recirculation
                                ) in allow_ue_recirculation_list:
                                    params = {
                                        "vlan_conf": vlan_conf,
                                        "pkt_type": pkt_type,
                                        "tagged1": tagged[0],
                                        "tagged2": tagged[1],
                                        "with_psc": with_psc,
                                        "is_next_hop_spine": is_next_hop_spine,
                                        "drop_reason": drop_reason,
                                        "prefix_len": prefix_len,
                                        "pkt_len": pkt_len,
                                        "send_report_to_spine": send_report_to_spine,
                                        "is_device_spine": is_device_spine,
                                        "allow_ue_recirculation": allow_ue_recirculation,
                                    }

                                    print(
                                        "Testing "
                                        + ", ".join(
                                            [
                                                "{}={}".format(k, v)
                                                for k, v in params.items()
                                                if (
                                                    v is not None
                                                    and k not in ["tagged1", "tagged2"]
                                                )
                                            ]
                                        )
                                    )
                                    tc_name = "_".join(
                                        [
                                            "{}_{}".format(k, v)
                                            for k, v in params.items()
                                        ]
                                    )
                                    params["tc_name"] = tc_name

                                    if int_test_type not in INT_OPTIONS:
                                        pkt = getattr(
                                            testutils, "simple_%s_packet" % pkt_type
                                        )(pktlen=pkt_len, **pkt_addrs)
                                    else:
                                        pkt = None
                                    params["pkt"] = pkt

                                    yield params


def slice_tc_concat(slice_id, tc):
    return (slice_id << TC_WIDTH) + tc


def pkt_set_dscp(pkt, slice_id=None, tc=None, dscp=None):
    assert IP in pkt, "Packet must be IPv4 to set DSCP"
    if dscp is None:
        # Concat slice_id and tc
        dscp = (slice_id << TC_WIDTH) + tc
    assert dscp < 2 ** 7, "DSCP does not fit in 6 bits"
    new_pkt = pkt.copy()
    new_pkt[IP].tos = testutils.ip_make_tos(tos=0, ecn=None, dscp=dscp)
    return new_pkt


class FabricTest(P4RuntimeTest):

    # An IP pool which will be shared by all FabricTests
    # Start from 172.16.0.0
    next_single_use_ips = 0xAC100000

    def __init__(self):
        super(FabricTest, self).__init__()
        self.next_mbr_id = 1

    def setUp(self):
        super(FabricTest, self).setUp()
        self.port1 = self.swports(0)
        self.port2 = self.swports(1)
        self.port3 = self.swports(2)
        self.port4 = self.swports(3)
        self.setup_switch_info()
        self.set_up_packet_in_mirror()

    def tearDown(self):
        self.reset_switch_info()
        self.reset_packet_in_mirror()
        P4RuntimeTest.tearDown(self)

    def get_next_mbr_id(self):
        mbr_id = self.next_mbr_id
        self.next_mbr_id = self.next_mbr_id + 1
        return mbr_id

    def get_single_use_ip(self):
        FabricTest.next_single_use_ips += 1
        return socket.inet_ntoa(struct.pack("!I", FabricTest.next_single_use_ips))

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

    @tvcreate("setup/set_up_packet_in_mirror")
    def set_up_packet_in_mirror(self):
        self.add_clone_group(PACKET_IN_MIRROR_ID, [self.cpu_port], store=False)

    @tvcreate("teardown/reset_packet_in_mirror")
    def reset_packet_in_mirror(self):
        self.delete_clone_group(PACKET_IN_MIRROR_ID, [self.cpu_port], store=False)

    def build_packet_out(
        self,
        pkt,
        port,
        cpu_loopback_mode=CPU_LOOPBACK_MODE_DISABLED,
        do_forwarding=False,
        queue_id=QUEUE_ID_SYSTEM,
    ):
        packet_out = p4runtime_pb2.PacketOut()
        packet_out.payload = bytes(pkt)
        # pad0
        pad_md = packet_out.metadata.add()
        pad_md.metadata_id = 1
        pad_md.value = stringify(0, 1)
        # egress_port
        port_md = packet_out.metadata.add()
        port_md.metadata_id = 2
        port_md.value = stringify(port, 2)
        # pad1
        pad_md = packet_out.metadata.add()
        pad_md.metadata_id = 3
        pad_md.value = stringify(0, 1)
        # queue_id
        queue_md = packet_out.metadata.add()
        queue_md.metadata_id = 4
        queue_md.value = stringify(queue_id, 1)
        # pad2
        pad_md = packet_out.metadata.add()
        pad_md.metadata_id = 5
        pad_md.value = stringify(0, 1)
        # cpu_loopback_mode
        cpu_loopback_mode_md = packet_out.metadata.add()
        cpu_loopback_mode_md.metadata_id = 6
        cpu_loopback_mode_md.value = stringify(cpu_loopback_mode, 1)
        # do_forwarding
        do_forwarding_md = packet_out.metadata.add()
        do_forwarding_md.metadata_id = 7
        do_forwarding_md.value = stringify(1 if do_forwarding else 0, 1)
        # pad3
        pad_md = packet_out.metadata.add()
        pad_md.metadata_id = 8
        pad_md.value = stringify(0, 2)
        # pad4
        pad_md = packet_out.metadata.add()
        pad_md.metadata_id = 9
        pad_md.value = stringify(0, 6)
        # ether type
        ether_type_md = packet_out.metadata.add()
        ether_type_md.metadata_id = 10
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
        self,
        port_id,
        vlan_id,
        port_type,
        tagged=False,
        double_tagged=False,
        inner_vlan_id=0,
    ):
        if double_tagged:
            self.set_ingress_port_vlan(
                ingress_port=port_id,
                vlan_id=vlan_id,
                vlan_valid=True,
                inner_vlan_id=inner_vlan_id,
                port_type=port_type,
            )
        elif tagged:
            self.set_ingress_port_vlan(
                ingress_port=port_id,
                vlan_id=vlan_id,
                vlan_valid=True,
                port_type=port_type,
            )
            self.set_egress_vlan(egress_port=port_id, vlan_id=vlan_id, push_vlan=True)
        else:
            self.set_ingress_port_vlan(
                ingress_port=port_id,
                vlan_valid=False,
                internal_vlan_id=vlan_id,
                port_type=port_type,
            )
            self.set_egress_vlan(egress_port=port_id, vlan_id=vlan_id, push_vlan=False)

    def set_ingress_port_vlan(
        self,
        ingress_port,
        vlan_valid=False,
        vlan_id=0,
        internal_vlan_id=0,
        inner_vlan_id=None,
        port_type=PORT_TYPE_EDGE,
    ):
        ingress_port_ = stringify(ingress_port, 2)
        vlan_valid_ = b"\x01" if vlan_valid else b"\x00"
        vlan_id_ = stringify(vlan_id, 2)
        vlan_id_mask_ = stringify(4095 if vlan_valid else 0, 2)
        new_vlan_id_ = stringify(internal_vlan_id, 2)
        action_name = "permit" if vlan_valid else "permit_with_internal_vlan"
        action_params = [("port_type", port_type)]
        if not vlan_valid:
            action_params.append(("vlan_id", new_vlan_id_))
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

    def set_keep_egress_vlan_config(self, egress_port, vlan_id):
        egress_port = stringify(egress_port, 2)
        vlan_id = stringify(vlan_id, 2)
        self.send_request_add_entry_to_action(
            "egress_next.egress_vlan",
            [self.Exact("vlan_id", vlan_id), self.Exact("eg_port", egress_port)],
            "egress_next.keep_vlan",
            [],
        )

    def set_forwarding_type(
        self,
        ingress_port,
        eth_dst=None,
        eth_dst_mask=MAC_MASK,
        ethertype=ETH_TYPE_IPV4,
        fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
    ):
        ingress_port_ = stringify(ingress_port, 2)
        priority = DEFAULT_PRIORITY
        if ethertype == ETH_TYPE_IPV4:
            ethertype_ = stringify(0, 2)
            ethertype_mask_ = stringify(0, 2)
            ip_eth_type = stringify(ethertype, 2)
        elif ethertype == ETH_TYPE_MPLS_UNICAST:
            ethertype_ = stringify(ETH_TYPE_MPLS_UNICAST, 2)
            ethertype_mask_ = stringify(0xFFFF, 2)
            # TODO: install rule for MPLS+IPv6 traffic
            ip_eth_type = stringify(ETH_TYPE_IPV4, 2)
            priority += 10
        else:
            raise Exception("Invalid ethertype")
        fwd_type_ = stringify(fwd_type, 1)
        matches = [
            self.Exact("ig_port", ingress_port_),
            self.Exact("ip_eth_type", ip_eth_type),
        ]
        if eth_dst is not None:
            eth_dst_ = mac_to_binary(eth_dst)
            eth_dst_mask_ = mac_to_binary(eth_dst_mask)
            matches.append(self.Ternary("eth_dst", eth_dst_, eth_dst_mask_))
        if ethertype_mask_ != b"\x00\x00":
            matches.append(self.Ternary("eth_type", ethertype_, ethertype_mask_))
        self.send_request_add_entry_to_action(
            "filtering.fwd_classifier",
            matches,
            "filtering.set_forwarding_type",
            [("fwd_type", fwd_type_)],
            priority=priority,
        )

    def set_up_recirc_ports(self):
        # All recirculation ports are configured as untagged with DEFAULT_VLAN
        # as the internal one.
        for port in RECIRCULATE_PORTS:
            self.set_ingress_port_vlan(
                ingress_port=port,
                vlan_valid=False,
                vlan_id=0,
                internal_vlan_id=DEFAULT_VLAN,
                port_type=PORT_TYPE_INTERNAL,
            )
            self.set_egress_vlan(port, DEFAULT_VLAN, push_vlan=False)
            self.set_forwarding_type(
                port, ethertype=ETH_TYPE_IPV4, fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )
            self.set_forwarding_type(
                port, ethertype=ETH_TYPE_MPLS_UNICAST, fwd_type=FORWARDING_TYPE_MPLS,
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

    def add_forwarding_acl_punt_to_cpu(
        self, eth_type=None, priority=DEFAULT_PRIORITY, post_ingress=False
    ):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask_ = stringify(0xFFFF, 2)
        action = "acl.punt_to_cpu_post_ingress" if post_ingress else "acl.punt_to_cpu"
        return self.send_request_add_entry_to_action(
            "acl.acl",
            [self.Ternary("eth_type", eth_type_, eth_type_mask_)],
            action,
            [],
            priority,
        )

    def read_forwarding_acl_punt_to_cpu(self, priority=DEFAULT_PRIORITY, **matches):
        matches = self.build_acl_matches(**matches)
        return self.read_table_entry("acl.acl", matches, priority)

    def add_forwarding_acl_set_output_port(
        self, output_port, priority=DEFAULT_PRIORITY, **matches
    ):
        matches = self.build_acl_matches(**matches)
        return self.send_request_add_entry_to_action(
            "acl.acl",
            matches,
            "acl.set_output_port",
            [("port_num", stringify(output_port, 2))],
            priority,
        )

    def read_forwarding_acl_punt_to_cpu(self, eth_type=None, priority=DEFAULT_PRIORITY):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask_ = stringify(0xFFFF, 2)
        mk = [self.Ternary("eth_type", eth_type_, eth_type_mask_)]
        return self.read_table_entry("acl.acl", mk, priority)

    def add_forwarding_acl_copy_to_cpu(self, eth_type=None, post_ingress=False):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask = stringify(0xFFFF, 2)
        action = "acl.copy_to_cpu_post_ingress" if post_ingress else "acl.copy_to_cpu"
        self.send_request_add_entry_to_action(
            "acl.acl",
            [self.Ternary("eth_type", eth_type_, eth_type_mask)],
            action,
            [],
            DEFAULT_PRIORITY,
        )

    def add_forwarding_acl_drop_ingress_port(self, ingress_port):
        ingress_port_ = stringify(ingress_port, 2)
        ingress_port_mask_ = stringify(0x1FF, 2)
        self.send_request_add_entry_to_action(
            "acl.acl",
            [self.Ternary("ig_port", ingress_port_, ingress_port_mask_)],
            "acl.drop",
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

    def add_forwarding_acl_drop(
        self, ipv4_src=None, ipv4_dst=None, ip_proto=None, l4_sport=None, l4_dport=None,
    ):
        # Send only if the match keys are not empty
        matches = self.build_acl_matches(
            ipv4_src, ipv4_dst, ip_proto, l4_sport, l4_dport
        )
        if matches:
            self.send_request_add_entry_to_action(
                "acl.acl", matches, "acl.drop", [], DEFAULT_PRIORITY,
            )

    def build_acl_matches(
        self,
        ipv4_src=None,
        ipv4_dst=None,
        ip_proto=None,
        l4_sport=None,
        l4_dport=None,
        ig_port=None,
    ):
        matches = []
        if ipv4_src is not None:
            ipv4_src_ = ipv4_to_binary(ipv4_src)
            ipv4_src_mask = stringify(0xFFFFFFFF, 4)
            matches.append(self.Ternary("ipv4_src", ipv4_src_, ipv4_src_mask))
        if ipv4_dst is not None:
            ipv4_dst_ = ipv4_to_binary(ipv4_dst)
            ipv4_dst_mask = stringify(0xFFFFFFFF, 4)
            matches.append(self.Ternary("ipv4_dst", ipv4_dst_, ipv4_dst_mask))
        if ip_proto is not None:
            ip_proto_ = stringify(ip_proto, 1)
            ip_proto_mask = stringify(0xFF, 1)
            matches.append(self.Ternary("ip_proto", ip_proto_, ip_proto_mask))
        if l4_sport is not None:
            l4_sport_ = stringify(l4_sport, 2)
            l4_sport_mask = stringify(0xFFFF, 2)
            matches.append(self.Ternary("l4_sport", l4_sport_, l4_sport_mask))
        if l4_dport is not None:
            l4_dport_ = stringify(l4_dport, 2)
            l4_dport_mask = stringify(0xFFFF, 2)
            matches.append(self.Ternary("l4_dport", l4_dport_, l4_dport_mask))
        if ig_port is not None:
            ig_port_ = stringify(ig_port, 2)
            ig_port_mask = stringify(0x01FF, 2)
            matches.append(self.Ternary("ig_port", ig_port_, ig_port_mask))
        return matches

    def add_forwarding_acl_next(
        self,
        next_id,
        ig_port_type,
        ipv4_src=None,
        ipv4_dst=None,
        ip_proto=None,
        l4_sport=None,
        l4_dport=None,
    ):
        # Send only if the match keys are not empty
        next_id_ = stringify(next_id, 4)
        ig_port_type_mask = b"\x03"
        matches = self.build_acl_matches(
            ipv4_src, ipv4_dst, ip_proto, l4_sport, l4_dport
        )
        matches.append(self.Ternary("ig_port_type", ig_port_type, ig_port_type_mask))
        if matches:
            self.send_request_add_entry_to_action(
                "acl.acl",
                matches,
                "acl.set_next_id_acl",
                [("next_id", next_id_)],
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
            "pre_next.next_vlan",
            [self.Exact("next_id", next_id_)],
            "pre_next.set_vlan",
            [("vlan_id", vlan_id_)],
        )

    def add_next_double_vlan(self, next_id, new_vlan_id, new_inner_vlan_id):
        next_id_ = stringify(next_id, 4)
        vlan_id_ = stringify(new_vlan_id, 2)
        inner_vlan_id_ = stringify(new_inner_vlan_id, 2)
        self.send_request_add_entry_to_action(
            "pre_next.next_vlan",
            [self.Exact("next_id", next_id_)],
            "pre_next.set_double_vlan",
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

    def add_next_mpls(self, next_id, label):
        next_id_ = stringify(next_id, 4)
        label_ = stringify(label, 3)
        self.send_request_add_entry_to_action(
            "pre_next.next_mpls",
            [self.Exact("next_id", next_id_)],
            "pre_next.set_mpls_label",
            [("label", label_),],
        )

    # next_hops is a list of tuples (egress_port, smac, dmac)
    def add_next_mpls_and_routing_group(self, next_id, grp_id, next_hops=None):
        actions = []
        if next_hops is not None:
            mpls_labels = list(map(lambda x: x[3], next_hops))
            if len(set(mpls_labels)) > 1:
                self.fail(
                    "More than one MPLS label passed to add_next_mpls_and_routing_group"
                )
            self.add_next_mpls(next_id, mpls_labels[0])

            for (egress_port, smac, dmac, _) in next_hops:
                egress_port_ = stringify(egress_port, 2)
                smac_ = mac_to_binary(smac)
                dmac_ = mac_to_binary(dmac)
                actions.append(
                    [
                        "next.routing_hashed",
                        [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_),],
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

    def write_clone_group(
        self, clone_id, ports, truncate_max_len, update_type, store=True
    ):
        req = self.get_new_write_request()
        update = req.updates.add()
        update.type = update_type
        pre_entry = update.entity.packet_replication_engine_entry
        clone_entry = pre_entry.clone_session_entry
        clone_entry.session_id = clone_id
        clone_entry.class_of_service = 0
        clone_entry.packet_length_bytes = truncate_max_len
        for port in ports:
            replica = clone_entry.replicas.add()
            replica.egress_port = port
            replica.instance = 0  # set to 0 because we don't support it yet.
        return req, self.write_request(req, store=store)

    def add_clone_group(self, clone_id, ports, truncate_max_len=0, store=True):
        self.write_clone_group(
            clone_id, ports, truncate_max_len, p4runtime_pb2.Update.INSERT, store=store
        )

    def delete_clone_group(self, clone_id, ports, store=True):
        self.write_clone_group(
            clone_id, ports, 0, p4runtime_pb2.Update.DELETE, store=store
        )

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
        self.setup_port(self.port1, vlan_id, PORT_TYPE_EDGE, tagged1)
        self.setup_port(self.port2, vlan_id, PORT_TYPE_EDGE, tagged2)
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
            self.setup_port(port, vlan_id, PORT_TYPE_EDGE, False)

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
        self.setup_port(self.port1, vlan_id, PORT_TYPE_EDGE, True)
        self.setup_port(self.port2, vlan_id, PORT_TYPE_EDGE, True)
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

        self.setup_port(self.port1, vlan_id_outer, PORT_TYPE_EDGE, tagged=True)
        self.setup_port(self.port2, vlan_id_outer, PORT_TYPE_EDGE, tagged=True)
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
    def set_up_ipv4_unicast_rules(
        self,
        next_hop_mac,
        ig_port,
        eg_port,
        dst_ipv4,
        tagged1=False,
        tagged2=False,
        prefix_len=24,
        next_id=100,
        is_next_hop_spine=False,
        routed_eth_types=(ETH_TYPE_IPV4,),
        install_routing_entry=True,
        port_type1=PORT_TYPE_EDGE,
        port_type2=PORT_TYPE_EDGE,
        from_packet_out=False,
        switch_mac=SWITCH_MAC,
        vlan1=VLAN_ID_1,
        vlan2=VLAN_ID_2,
        mpls_label=MPLS_LABEL_2,
    ):

        group_id = next_id

        # Setup ports.
        self.setup_port(ig_port, vlan1, port_type1, tagged1)
        # This is to prevent sending duplicate table entries for tests like
        # FabricIntDeflectedDropTest, where we already set up the recirculation port as
        # part of `set_up_int_flows()`.
        if eg_port not in RECIRCULATE_PORTS:
            self.setup_port(eg_port, vlan2, port_type2, tagged2)

        # Forwarding type -> routing v4
        # If from_packet_out, set eth_dst to don't care. All packet-outs should
        # be routed, independently of eth_dst.
        for eth_type in routed_eth_types:
            self.set_forwarding_type(
                ig_port,
                switch_mac if not from_packet_out else None,
                ethertype=eth_type,
                fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )

        # Routing entry.
        if install_routing_entry:
            self.add_forwarding_routing_v4_entry(dst_ipv4, prefix_len, next_id)

        if not is_next_hop_spine:
            self.add_next_routing(next_id, eg_port, switch_mac, next_hop_mac)
            self.add_next_vlan(next_id, vlan2)
        else:
            params = [eg_port, switch_mac, next_hop_mac, mpls_label]
            self.add_next_mpls_and_routing_group(next_id, group_id, [params])
            self.add_next_vlan(next_id, DEFAULT_VLAN)

    def build_exp_ipv4_unicast_packet(
        self,
        pkt,
        next_hop_mac,
        switch_mac=SWITCH_MAC,
        exp_pkt_base=None,
        is_next_hop_spine=False,
        tagged2=False,
        vlan2=DEFAULT_VLAN,
        mpls_label=MPLS_LABEL_2,
        routed=True,
    ):
        # Build exp pkt using the input one.
        exp_pkt = pkt.copy() if not exp_pkt_base else exp_pkt_base
        # Route
        exp_pkt[Ether].src = switch_mac
        exp_pkt[Ether].dst = next_hop_mac
        if not is_next_hop_spine and routed:
            exp_pkt = pkt_decrement_ttl(exp_pkt)
        if tagged2 and Dot1Q not in exp_pkt:
            exp_pkt = pkt_add_vlan(exp_pkt, vlan_vid=vlan2)
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, label=mpls_label, ttl=DEFAULT_MPLS_TTL)
        return exp_pkt

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
        install_routing_entry=True,
        override_eg_port=None,
        port_type1=PORT_TYPE_EDGE,
        port_type2=PORT_TYPE_EDGE,
        from_packet_out=False,
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
        :param install_routing_entry: install entry to routing table
        :param override_eg_port: to override the default or the provided eg port
        :param port_type1: port type to be used for the programming of the ig port
        :param port_type2: port type to be used for the programming of the eg port
        :param from_packet_out: ingress packet is a packet-out (enables do_forwarding)
        """
        if IP not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv4 test with packet that is not IP")
        if is_next_hop_spine and tagged2:
            self.fail("Cannot do MPLS test with egress port tagged (tagged2)")
        if ig_port is None:
            ig_port = self.port1
        if eg_port is None:
            eg_port = self.port2
        if from_packet_out:
            ig_port = self.cpu_port
            port_type1 = PORT_TYPE_INTERNAL

        # If the input pkt has a VLAN tag, use that to configure tables.
        pkt_is_tagged = False
        if Dot1Q in pkt:
            vlan1 = pkt[Dot1Q].vlan
            tagged1 = True
            pkt_is_tagged = True
            # packet-outs should be untagged
            assert not from_packet_out
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
        mpls_label = MPLS_LABEL_2
        if dst_ipv4 is None:
            dst_ipv4 = pkt[IP].dst
        if from_packet_out:
            switch_mac = SWITCH_MAC
        else:
            switch_mac = pkt[Ether].dst

        self.set_up_ipv4_unicast_rules(
            next_hop_mac,
            ig_port,
            eg_port,
            dst_ipv4,
            tagged1,
            tagged2,
            prefix_len,
            next_id,
            is_next_hop_spine,
            routed_eth_types,
            install_routing_entry,
            port_type1,
            port_type2,
            from_packet_out,
            switch_mac,
            vlan1,
            vlan2,
            mpls_label,
        )

        if exp_pkt is None:
            exp_pkt = self.build_exp_ipv4_unicast_packet(
                pkt,
                next_hop_mac,
                switch_mac,
                exp_pkt_base,
                is_next_hop_spine,
                tagged2,
                vlan2,
                mpls_label,
            )

        if tagged1 and not pkt_is_tagged:
            pkt = pkt_add_vlan(pkt, vlan_vid=vlan1)

        if no_send:
            return

        if from_packet_out:
            self.send_packet_out(
                self.build_packet_out(pkt=pkt, port=0, do_forwarding=True)
            )
        else:
            self.send_packet(ig_port, pkt)

        verify_port = eg_port
        if override_eg_port:
            verify_port = override_eg_port

        if verify_pkt:
            self.verify_packet(exp_pkt, verify_port)

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
        self.setup_port(in_port, internal_in_vlan, PORT_TYPE_EDGE, in_vlan is not None)
        for out_port in out_ports:
            self.setup_port(
                out_port, internal_out_vlan, PORT_TYPE_INFRA, out_vlan is not None
            )

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
        self.setup_port(
            self.port1, vlan_id=in_vlan, port_type=PORT_TYPE_INFRA, tagged=in_tagged
        )
        # Setup port 2: packets on this port are double tagged packets
        self.setup_port(
            self.port2,
            vlan_id=next_vlan_id,
            port_type=PORT_TYPE_EDGE,
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
            port_type=PORT_TYPE_EDGE,
            double_tagged=True,
            inner_vlan_id=inner_vlan_id,
        )
        # Setup port 2
        self.setup_port(
            self.port2, vlan_id=next_vlan, port_type=PORT_TYPE_INFRA, tagged=out_tagged
        )

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
            self.add_next_mpls_and_routing_group(next_id, group_id, [params])
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
        self.setup_port(self.port1, DEFAULT_VLAN, PORT_TYPE_INFRA, False)
        self.setup_port(self.port2, DEFAULT_VLAN, PORT_TYPE_INFRA, False)
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
            self.add_next_mpls_and_routing_group(next_id, group_id, [params])

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

    def _add_spgw_iface(
        self, iface_addr, prefix_len, iface_type, gtpu_valid, slice_id=DEFAULT_SLICE_ID
    ):
        req = self.get_new_write_request()

        iface_addr_ = ipv4_to_binary(iface_addr)

        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.interfaces",
            [
                self.Lpm("ipv4_dst_addr", iface_addr_, prefix_len),
                self.Exact("gtpu_is_valid", stringify(int(gtpu_valid), 1)),
            ],
            "FabricIngress.spgw." + iface_type,
            [("slice_id", stringify(slice_id, 1)),],
        )
        self.write_request(req)

    def add_ue_pool(self, pool_addr, prefix_len=32, slice_id=DEFAULT_SLICE_ID):
        self._add_spgw_iface(
            iface_addr=pool_addr,
            prefix_len=prefix_len,
            iface_type=SPGW_IFACE_CORE,
            gtpu_valid=False,
            slice_id=slice_id,
        )

    def add_s1u_iface(self, s1u_addr, prefix_len=32, slice_id=DEFAULT_SLICE_ID):
        self._add_spgw_iface(
            iface_addr=s1u_addr,
            prefix_len=prefix_len,
            iface_type=SPGW_IFACE_ACCESS,
            gtpu_valid=True,
            slice_id=slice_id,
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
            iface_type=SPGW_IFACE_FROM_DBUF,
            gtpu_valid=True,
        )

        # FAR that tunnels to the dbuf device
        return self._add_far(
            dbuf_far_id,
            "FabricIngress.spgw.load_dbuf_far",
            [
                ("drop", stringify(0, 1)),
                ("teid", stringify(dbuf_teid, 4)),
                ("tunnel_src_port", stringify(UDP_GTP_PORT, 2)),
                ("tunnel_src_addr", ipv4_to_binary(drain_dst_addr)),
                ("tunnel_dst_addr", ipv4_to_binary(dbuf_addr)),
            ],
        )

    def add_uplink_pdr(self, ctr_id, far_id, teid, tunnel_dst_addr, tc=DEFAULT_TC):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.uplink_pdrs",
            [
                self.Exact("teid", stringify(teid, 4)),
                self.Exact("tunnel_ipv4_dst", ipv4_to_binary(tunnel_dst_addr)),
            ],
            "FabricIngress.spgw.load_pdr_decap",
            [
                ("ctr_id", stringify(ctr_id, 2)),
                ("far_id", stringify(far_id, 4)),
                ("tc", stringify(tc, 1)),
            ],
        )
        self.write_request(req)

    def add_uplink_recirc_rule(
        self, ipv4_dst_and_mask, ipv4_src_and_mask=None, allow=True, priority=1
    ):
        req = self.get_new_write_request()
        match = [
            self.Ternary(
                "ipv4_dst",
                ipv4_to_binary(ipv4_dst_and_mask[0]),
                ipv4_to_binary(ipv4_dst_and_mask[1]),
            ),
        ]
        if ipv4_src_and_mask is not None:
            match.append(
                self.Ternary(
                    "ipv4_src",
                    ipv4_to_binary(ipv4_src_and_mask[0]),
                    ipv4_to_binary(ipv4_src_and_mask[1]),
                ),
            )
        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.uplink_recirc_rules",
            match,
            "FabricIngress.spgw.recirc_" + ("allow" if allow else "deny"),
            [],
            priority,
        )
        self.write_request(req)

    def add_downlink_pdr(self, ctr_id, far_id, ue_addr, tc=DEFAULT_TC):
        req = self.get_new_write_request()

        self.push_update_add_entry_to_action(
            req,
            "FabricIngress.spgw.downlink_pdrs",
            [self.Exact("ue_addr", ipv4_to_binary(ue_addr))],
            "FabricIngress.spgw.load_pdr",
            [
                ("ctr_id", stringify(ctr_id, 2)),
                ("far_id", stringify(far_id, 4)),
                ("tc", stringify(tc, 1)),
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

    def add_normal_far(self, far_id, drop=False):
        return self._add_far(
            far_id,
            "FabricIngress.spgw.load_normal_far",
            [("drop", stringify(drop, 1))],
        )

    def add_tunnel_far(
        self,
        far_id,
        teid,
        tunnel_src_addr,
        tunnel_dst_addr,
        tunnel_src_port=DEFAULT_GTP_TUNNEL_SPORT,
        drop=False,
    ):
        return self._add_far(
            far_id,
            "FabricIngress.spgw.load_tunnel_far",
            [
                ("drop", stringify(drop, 1)),
                ("teid", stringify(teid, 4)),
                ("tunnel_src_port", stringify(tunnel_src_port, 2)),
                ("tunnel_src_addr", ipv4_to_binary(tunnel_src_addr)),
                ("tunnel_dst_addr", ipv4_to_binary(tunnel_dst_addr)),
            ],
        )

    def setup_uplink(
        self,
        s1u_sgw_addr,
        teid,
        ctr_id,
        far_id=UPLINK_FAR_ID,
        slice_id=DEFAULT_SLICE_ID,
        tc=DEFAULT_TC,
    ):
        self.add_s1u_iface(s1u_addr=s1u_sgw_addr, slice_id=slice_id)
        self.add_uplink_pdr(
            ctr_id=ctr_id, far_id=far_id, teid=teid, tunnel_dst_addr=s1u_sgw_addr, tc=tc
        )
        self.add_normal_far(far_id=far_id)

    def setup_downlink(
        self,
        s1u_sgw_addr,
        s1u_enb_addr,
        teid,
        ue_addr,
        ctr_id,
        far_id=DOWNLINK_FAR_ID,
        slice_id=DEFAULT_SLICE_ID,
        tc=DEFAULT_TC,
    ):
        self.add_ue_pool(pool_addr=ue_addr, slice_id=slice_id)
        self.add_downlink_pdr(ctr_id=ctr_id, far_id=far_id, ue_addr=ue_addr, tc=tc)
        self.add_tunnel_far(
            far_id=far_id,
            teid=teid,
            tunnel_src_addr=s1u_sgw_addr,
            tunnel_dst_addr=s1u_enb_addr,
        )

    def enable_encap_with_psc(self, qfi=0):
        self.send_request_add_entry_to_action(
            "FabricEgress.spgw.gtpu_encap",
            None,
            "FabricEgress.spgw.gtpu_with_psc",
            [("qfi", stringify(qfi, 1))],
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

    def runUplinkTest(
        self,
        ue_out_pkt,
        tagged1,
        tagged2,
        with_psc,
        is_next_hop_spine,
        slice_id=DEFAULT_SLICE_ID,
        tc=DEFAULT_TC,
        dscp_rewrite=False,
        verify_counters=True,
        eg_port=None,
    ):
        upstream_mac = HOST2_MAC

        gtp_pkt = pkt_add_gtp(
            ue_out_pkt,
            out_ipv4_src=S1U_ENB_IPV4,
            out_ipv4_dst=S1U_SGW_IPV4,
            teid=UPLINK_TEID,
            ext_psc_type=GTPU_EXT_PSC_TYPE_UL if with_psc else None,
            ext_psc_qfi=0,
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
        if dscp_rewrite:
            exp_pkt = pkt_set_dscp(exp_pkt, slice_id=slice_id, tc=tc)

        self.setup_uplink(
            s1u_sgw_addr=S1U_SGW_IPV4,
            teid=UPLINK_TEID,
            ctr_id=UPLINK_PDR_CTR_IDX,
            slice_id=slice_id,
            tc=tc,
        )

        if verify_counters:
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
            eg_port=eg_port,
        )

        if not verify_counters:
            return

        ingress_bytes = len(gtp_pkt) + ETH_FCS_BYTES
        if tagged1:
            ingress_bytes += VLAN_BYTES
        if self.loopback:
            ingress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES
        # Counters are updated with bytes seen at egress parser. GTP decap
        # happens at ingress deparser. VLAN/MPLS push/pop happens at egress
        # deparser, hence not reflected in counter increment.
        egress_bytes = (
            ingress_bytes + BMD_BYTES - IP_HDR_BYTES - UDP_HDR_BYTES - GTPU_HDR_BYTES
        )
        if with_psc:
            egress_bytes = egress_bytes - GTPU_OPTIONS_HDR_BYTES - GTPU_EXT_PSC_BYTES

        # Verify the Ingress and Egress PDR counters
        self.verify_pdr_counters(UPLINK_PDR_CTR_IDX, ingress_bytes, egress_bytes, 1, 1)

    def runUplinkRecircTest(
        self, ue_out_pkt, allow, tagged1, tagged2, is_next_hop_spine
    ):
        # Input GTP-encapped packet.
        pkt = pkt_add_gtp(
            ue_out_pkt,
            out_ipv4_src=S1U_ENB_IPV4,
            out_ipv4_dst=S1U_SGW_IPV4,
            teid=UPLINK_TEID,
        )
        pkt[Ether].src = S1U_ENB_MAC
        pkt[Ether].dst = SWITCH_MAC

        # Output, still GTP-encapped. Recirculation means routed twice, one time
        # for uplink, another for downlink.
        if not is_next_hop_spine:
            ue_out_pkt[IP].ttl = ue_out_pkt[IP].ttl - 2
        else:
            # TTL decremented only for uplink. For downlink, it will be up to
            # dest leaf to decrement after popping the MPLS label.
            ue_out_pkt[IP].ttl = ue_out_pkt[IP].ttl - 1
        exp_pkt = pkt_add_gtp(
            ue_out_pkt,
            out_ipv4_src=S1U_SGW_IPV4,
            out_ipv4_dst=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
        )
        exp_pkt[Ether].src = SWITCH_MAC
        exp_pkt[Ether].dst = S1U_ENB_MAC
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)

        self.setup_uplink(
            s1u_sgw_addr=S1U_SGW_IPV4, teid=UPLINK_TEID, ctr_id=UPLINK_PDR_CTR_IDX,
        )

        self.setup_downlink(
            s1u_sgw_addr=S1U_SGW_IPV4,
            s1u_enb_addr=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
            ue_addr=UE2_IPV4,
            ctr_id=DOWNLINK_PDR_CTR_IDX,
        )

        self.set_up_recirc_ports()

        # By default deny all UE-to-UE communication.
        self.add_uplink_recirc_rule(
            ipv4_dst_and_mask=(UE_SUBNET, UE_SUBNET_MASK), allow=False, priority=1
        )
        if allow:
            # Allow only for specific UEs.
            self.add_uplink_recirc_rule(
                ipv4_src_and_mask=(UE1_IPV4, "255.255.255.255"),
                ipv4_dst_and_mask=(UE2_IPV4, "255.255.255.255"),
                allow=True,
                priority=10,
            )

        # Clear SPGW counters before sending the packet
        self.reset_pdr_counters(UPLINK_PDR_CTR_IDX)
        self.reset_pdr_counters(DOWNLINK_PDR_CTR_IDX)

        self.runIPv4UnicastTest(
            pkt=pkt,
            dst_ipv4=S1U_ENB_IPV4,
            next_hop_mac=S1U_ENB_MAC,
            prefix_len=32,
            exp_pkt=exp_pkt,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            verify_pkt=allow,
        )

        uplink_ingress_bytes = len(pkt) + ETH_FCS_BYTES
        uplink_egress_bytes = (
            uplink_ingress_bytes
            + BMD_BYTES
            - IP_HDR_BYTES
            - UDP_HDR_BYTES
            - GTPU_HDR_BYTES
        )
        downlink_ingress_bytes = uplink_egress_bytes - BMD_BYTES
        # Egress counters are updated with bytes seen at egress parser. GTP
        # encap happens at egress deparser, hence not reflected in uplink
        # counter increment.
        downlink_egress_bytes = downlink_ingress_bytes + BMD_BYTES

        # Uplink output/downlink input is always untagged (recirculation
        # port). tagged1 refers only to uplink input.
        if tagged1:
            # Pkt stays tagged all the way to egress pipe, popped by egress
            # deparser, after counter update.
            uplink_ingress_bytes += VLAN_BYTES
            uplink_egress_bytes += VLAN_BYTES
        if self.loopback:
            uplink_ingress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES
            uplink_egress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES
            downlink_ingress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES
            downlink_egress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES

        if allow:
            self.verify_pdr_counters(
                UPLINK_PDR_CTR_IDX, uplink_ingress_bytes, uplink_egress_bytes, 1, 1
            )
            self.verify_pdr_counters(
                DOWNLINK_PDR_CTR_IDX,
                downlink_ingress_bytes,
                downlink_egress_bytes,
                1,
                1,
            )
        else:
            # Only uplink ingress should be incremented.
            self.verify_pdr_counters(UPLINK_PDR_CTR_IDX, uplink_ingress_bytes, 0, 1, 0)
            self.verify_pdr_counters(DOWNLINK_PDR_CTR_IDX, 0, 0, 0, 0)

    def runDownlinkTest(
        self,
        pkt,
        tagged1,
        tagged2,
        with_psc,
        is_next_hop_spine,
        slice_id=DEFAULT_SLICE_ID,
        tc=DEFAULT_TC,
        dscp_rewrite=False,
        verify_counters=True,
        eg_port=None,
    ):
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
            ext_psc_type=GTPU_EXT_PSC_TYPE_DL if with_psc else None,
            ext_psc_qfi=0,
        )
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)
        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)
        if dscp_rewrite:
            # Modify outer IPV4
            exp_pkt = pkt_set_dscp(exp_pkt, slice_id=slice_id, tc=tc)

        self.setup_downlink(
            s1u_sgw_addr=S1U_SGW_IPV4,
            s1u_enb_addr=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
            ue_addr=UE1_IPV4,
            ctr_id=DOWNLINK_PDR_CTR_IDX,
            slice_id=slice_id,
            tc=tc,
        )

        if with_psc:
            self.enable_encap_with_psc()

        if verify_counters:
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
            eg_port=eg_port,
        )

        if not verify_counters:
            return

        ingress_bytes = len(pkt) + ETH_FCS_BYTES
        if tagged1:
            ingress_bytes += VLAN_BYTES
        if self.loopback:
            ingress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES
        # Egress sees same bytes as ingress. GTP encap and VLAN/MPLS push/pop
        # happen at egress deparser, hence after counter update
        egress_bytes = ingress_bytes + BMD_BYTES

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
        self.add_ue_pool(UE1_IPV4)
        self.add_downlink_pdr(
            ctr_id=DOWNLINK_PDR_CTR_IDX, far_id=DBUF_FAR_ID, ue_addr=UE1_IPV4
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
            ingress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES

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
            ue_addr=UE1_IPV4,
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

        # NOTE: ingress_bytes should be 0. as the switch should not update the
        #  ingress counter for packets coming **from** dbuf, since we already
        #  updated it when first sending the same packets **to** dbuf. However,
        #  to improve Tofino resource utilization, we decided to allow for
        #  accounting inaccuracy. See comment in spgw.p4 for more context.
        ingress_bytes = len(pkt_from_dbuf) + ETH_FCS_BYTES
        # GTP encap and VLAN/MPLS push/pop happen at egress deparser, but
        # counters are updated with bytes seen at egress parser.
        egress_bytes = (
            len(pkt_from_dbuf)
            + ETH_FCS_BYTES
            + BMD_BYTES
            - IP_HDR_BYTES
            - UDP_HDR_BYTES
            - GTPU_HDR_BYTES
        )
        if tagged1:
            ingress_bytes += VLAN_BYTES
            egress_bytes += VLAN_BYTES
        if self.loopback:
            egress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES

        # Verify the Ingress PDR packet counter did not increase, but the
        # egress did
        self.verify_pdr_counters(
            DOWNLINK_PDR_CTR_IDX, ingress_bytes, egress_bytes, 1, 1
        )


class IntTest(IPv4UnicastTest):
    """
    This test includes two parts:
    1. Reusing IPv4 unicast routing test to install routing entries,
       emitting the packet, and check the expected routed packet.
    2. Installs INT related table entries and create an expected INT report
       packet to verify the output.
    """

    def set_up_report_flow_with_report_type_and_bmd_type(
        self,
        src_ip,
        mon_ip,
        mon_port,
        report_type,
        bmd_type,
        switch_id,
        mirror_type,
        mon_label,
    ):
        action = ""
        # local report or queue report or both
        if (report_type & (INT_REPORT_TYPE_FLOW | INT_REPORT_TYPE_QUEUE)) != 0:
            action = "do_local_report_encap"
        elif report_type == INT_REPORT_TYPE_DROP:
            action = "do_drop_report_encap"
        else:
            self.fail("Invalid report type {}".format(report_type))

        action_params = [
            ("src_ip", ipv4_to_binary(src_ip)),
            ("mon_ip", ipv4_to_binary(mon_ip)),
            ("mon_port", stringify(mon_port, 2)),
            ("switch_id", stringify(switch_id, 4)),
        ]
        if mon_label:
            action = action + "_mpls"
            action_params.append(("mon_label", stringify(mon_label, 3)))

        self.send_request_add_entry_to_action(
            "report",
            [
                self.Exact("bmd_type", stringify(bmd_type, 1)),
                self.Exact("mirror_type", stringify(mirror_type, 1)),
                self.Exact("int_report_type", stringify(report_type, 1)),
            ],
            action,
            action_params,
        )

    def set_up_report_flow(self, src_ip, mon_ip, mon_port, switch_id, mon_label=None):
        def set_up_report_flow_internal(bmd_type, mirror_type, report_type):
            self.set_up_report_flow_with_report_type_and_bmd_type(
                src_ip,
                mon_ip,
                mon_port,
                report_type,
                bmd_type,
                switch_id,
                mirror_type,
                mon_label,
            )

        set_up_report_flow_internal(
            BRIDGED_MD_TYPE_INT_INGRESS_DROP, MIRROR_TYPE_INVALID, INT_REPORT_TYPE_DROP
        )
        set_up_report_flow_internal(
            BRIDGED_MD_TYPE_EGRESS_MIRROR, MIRROR_TYPE_INT_REPORT, INT_REPORT_TYPE_DROP
        )
        set_up_report_flow_internal(
            BRIDGED_MD_TYPE_EGRESS_MIRROR, MIRROR_TYPE_INT_REPORT, INT_REPORT_TYPE_FLOW
        )
        set_up_report_flow_internal(
            BRIDGED_MD_TYPE_DEFLECTED, MIRROR_TYPE_INVALID, INT_REPORT_TYPE_DROP
        )
        set_up_report_flow_internal(
            BRIDGED_MD_TYPE_EGRESS_MIRROR, MIRROR_TYPE_INT_REPORT, INT_REPORT_TYPE_QUEUE
        )
        set_up_report_flow_internal(
            BRIDGED_MD_TYPE_EGRESS_MIRROR,
            MIRROR_TYPE_INT_REPORT,
            INT_REPORT_TYPE_QUEUE | INT_REPORT_TYPE_FLOW,
        )

    def set_up_report_mirror_flow(self, pipe_id, mirror_id, port):
        self.add_clone_group(mirror_id, [port], INT_MIRROR_TRUNCATE_MAX_LEN)
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
            "FabricEgress.int_egress.config",
            [],
            "FabricEgress.int_egress.set_config",
            [
                ("hop_latency_mask", stringify(hop_latency_mask, 4)),
                ("timestamp_mask", stringify(timestamp_mask, 6)),
            ],
        )

    def set_up_watchlist_flow(
        self,
        ipv4_src=None,
        ipv4_dst=None,
        sport=None,
        dport=None,
        collector_action=False,
    ):
        ipv4_mask = ipv4_to_binary("255.255.255.255")
        # Use full range of TCP/UDP ports by default.
        sport_low = stringify(0, 2)
        sport_high = stringify(0xFFFF, 2)
        dport_low = stringify(0, 2)
        dport_high = stringify(0xFFFF, 2)

        lower_bound = stringify(0, 2)
        upper_bound = stringify(0xFFFF, 2)

        if sport:
            sport_low = stringify(sport, 2)
            sport_high = stringify(sport, 2)

        if dport:
            dport_low = stringify(dport, 2)
            dport_high = stringify(dport, 2)

        if collector_action:
            action = "no_report_collector"
        else:
            action = "mark_to_report"

        matches = [self.Exact("ipv4_valid", stringify(1, 1))]
        if ipv4_src is not None:
            ipv4_src_ = ipv4_to_binary(ipv4_src)
            matches.append(self.Ternary("ipv4_src", ipv4_src_, ipv4_mask))
        if ipv4_dst is not None:
            ipv4_dst_ = ipv4_to_binary(ipv4_dst)
            matches.append(self.Ternary("ipv4_dst", ipv4_dst_, ipv4_mask))
        if sport_low != lower_bound or sport_high != upper_bound:
            matches.append(self.Range("l4_sport", sport_low, sport_high))
        if dport_low != lower_bound or dport_high != upper_bound:
            matches.append(self.Range("l4_dport", dport_low, dport_high))

        self.send_request_add_entry_to_action(
            "watchlist", matches, action, [], priority=DEFAULT_PRIORITY,
        )

    def truncate_packet(self, pkt, size):
        pkt = bytes(pkt)
        if len(pkt) > size:
            pkt = pkt[:size]
        return pkt

    def build_int_local_report(
        self,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        ig_port,
        eg_port,
        sw_id,
        int_pre_mirrored_packet,
        is_device_spine,
        send_report_to_spine,
        f_flag=1,
        q_flag=0,
    ):
        # Mirrored packet will be truncated first
        inner_packet = Ether(
            bytes(int_pre_mirrored_packet)[
                : INT_MIRROR_TRUNCATE_MAX_LEN - INT_MIRROR_BYTES
            ]
        )
        # The switch should always strip VLAN, MPLS, GTP-U and VXLAN headers inside INT reports.
        if GTP_U_Header in inner_packet:
            inner_packet = pkt_remove_gtp(inner_packet)
        elif VXLAN in inner_packet:
            inner_packet = pkt_remove_vxlan(inner_packet)
        if Dot1Q in inner_packet:
            inner_packet = pkt_remove_vlan(inner_packet)
        if MPLS in inner_packet:
            inner_packet = pkt_remove_mpls(inner_packet)

        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=64, tos=INT_TOS)
            / UDP(sport=0, chksum=0)
            / INT_L45_REPORT_FIXED(nproto=2, f=f_flag, q=q_flag, hw_id=(eg_port >> 7))
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
        # IPv4 identification
        # The reason we also ignore IP checksum is because the `id` field is
        # random.
        mask_pkt.set_do_not_care_scapy(IP, "id")
        mask_pkt.set_do_not_care_scapy(IP, "chksum")
        mask_pkt.set_do_not_care_scapy(UDP, "chksum")
        mask_pkt.set_do_not_care_scapy(INT_L45_REPORT_FIXED, "ingress_tstamp")
        mask_pkt.set_do_not_care_scapy(INT_L45_REPORT_FIXED, "seq_no")
        mask_pkt.set_do_not_care_scapy(INT_L45_LOCAL_REPORT, "queue_id")
        mask_pkt.set_do_not_care_scapy(INT_L45_LOCAL_REPORT, "queue_occupancy")
        mask_pkt.set_do_not_care_scapy(INT_L45_LOCAL_REPORT, "egress_tstamp")

        return mask_pkt

    def build_int_drop_report(
        self,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        ig_port,
        eg_port,
        drop_reason,
        sw_id,
        int_pre_mirrored_packet,
        is_device_spine,
        send_report_to_spine,
        hw_id,
        truncate=True,
    ):
        if truncate:
            inner_packet = Ether(
                bytes(int_pre_mirrored_packet)[
                    : INT_MIRROR_TRUNCATE_MAX_LEN - INT_MIRROR_BYTES
                ]
            )
        else:
            inner_packet = int_pre_mirrored_packet
        # The switch should always strip VLAN, MPLS, GTP-U and VXLAN headers inside INT reports.
        if GTP_U_Header in inner_packet:
            inner_packet = pkt_remove_gtp(inner_packet)
        elif VXLAN in inner_packet:
            inner_packet = pkt_remove_vxlan(inner_packet)
        if Dot1Q in inner_packet:
            inner_packet = pkt_remove_vlan(inner_packet)
        if MPLS in inner_packet:
            inner_packet = pkt_remove_mpls(inner_packet)

        # Note: scapy doesn't support dscp field, use tos.
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=64, tos=INT_TOS)
            / UDP(sport=0, chksum=0)
            / INT_L45_REPORT_FIXED(nproto=1, d=1, hw_id=hw_id)
            / INT_L45_DROP_REPORT(
                switch_id=sw_id,
                ingress_port_id=ig_port,
                egress_port_id=eg_port,
                drop_reason=drop_reason,
                pad=0,
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
        # IPv4 identification
        # The reason we also ignore IP checksum is because the `id` field is
        # random.
        mask_pkt.set_do_not_care_scapy(IP, "id")
        mask_pkt.set_do_not_care_scapy(IP, "chksum")
        mask_pkt.set_do_not_care_scapy(UDP, "chksum")
        mask_pkt.set_do_not_care_scapy(INT_L45_REPORT_FIXED, "ingress_tstamp")
        mask_pkt.set_do_not_care_scapy(INT_L45_REPORT_FIXED, "seq_no")
        mask_pkt.set_do_not_care_scapy(INT_L45_DROP_REPORT, "queue_id")
        mask_pkt.set_do_not_care_scapy(INT_L45_DROP_REPORT, "queue_occupancy")
        mask_pkt.set_do_not_care_scapy(INT_L45_DROP_REPORT, "egress_tstamp")
        mask_pkt.set_do_not_care_scapy(INT_L45_DROP_REPORT, "pad")
        return mask_pkt

    def set_up_report_table_entries(
        self, collector_port, is_device_spine, send_report_to_spine
    ):
        self.setup_port(collector_port, DEFAULT_VLAN, PORT_TYPE_INFRA)

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
                self.add_next_mpls_and_routing_group(next_id, group_id, [params])
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
                self.add_next_mpls_and_routing_group(next_id, group_id, [params])
            else:
                # Leaf to host
                self.add_next_routing(
                    next_id, collector_port, SWITCH_MAC, INT_COLLECTOR_MAC
                )
        self.add_next_vlan(next_id, DEFAULT_VLAN)

    def set_up_int_flows(
        self, is_device_spine, pkt, send_report_to_spine, watch_flow=True
    ):
        if pkt:
            # Watchlist always matches on inner headers.
            if GTP_U_Header in pkt:
                pkt = pkt_remove_gtp(pkt)
            elif VXLAN in pkt:
                pkt = pkt_remove_vxlan(pkt)

            if UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            elif TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            else:
                sport = None
                dport = None

            if watch_flow:
                self.set_up_watchlist_flow(pkt[IP].src, pkt[IP].dst, sport, dport)
        self.set_up_report_flow(
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            INT_REPORT_PORT,
            SWITCH_ID,
            MPLS_LABEL_1 if is_device_spine else None,
        )
        for i in range(0, 4):
            self.set_up_report_mirror_flow(
                i, INT_REPORT_MIRROR_IDS[i], RECIRCULATE_PORTS[i]
            )
        self.set_up_report_table_entries(
            self.port3, is_device_spine, send_report_to_spine
        )
        self.set_up_recirc_ports()

    def set_up_latency_threshold_for_q_report(
        self, threshold_trigger, threshold_reset, queue_id=0
    ):
        def set_up_queue_report_table_internal(upper, lower, action):
            # Omit dont'care matches
            matches = [self.Exact("egress_qid", stringify(queue_id, 1))]
            if upper[0] != 0 or upper[1] != 0xFFFF:
                matches.append(
                    self.Range("hop_latency_upper", *[stringify(v, 2) for v in upper])
                )
            if lower[0] != 0 or lower[1] != 0xFFFF:
                matches.append(
                    self.Range("hop_latency_lower", *[stringify(v, 2) for v in lower])
                )
            self.send_request_add_entry_to_action(
                "FabricEgress.int_egress.queue_latency_thresholds",
                matches,
                action,
                [],
                DEFAULT_PRIORITY,
            )

        if threshold_trigger <= 0xFFFF:
            # from threshold to 0xffff
            set_up_queue_report_table_internal(
                [0, 0], [threshold_trigger, 0xFFFF], "check_quota"
            )
            # from 0x10000 to 32-bit max
            set_up_queue_report_table_internal([1, 0xFFFF], [0, 0xFFFF], "check_quota")
        else:
            threshold_upper = threshold_trigger >> 16
            threshold_lower = threshold_trigger & 0xFFFF
            # from lower 16-bit of threshold to 0xffff
            set_up_queue_report_table_internal(
                [threshold_upper, threshold_upper],
                [threshold_lower, 0xFFFF],
                "check_quota",
            )
            if threshold_upper != 0xFFFF:
                # from upper 16-bit of threshold + 1 to 32-bit max
                set_up_queue_report_table_internal(
                    [threshold_upper + 1, 0xFFFF], [0, 0xFFFF], "check_quota"
                )

        if threshold_reset <= 0xFFFF:
            # reset quota if latency is below threshold
            threshold_reset = threshold_reset - 1 if threshold_reset > 0 else 0
            set_up_queue_report_table_internal(
                [0, 0], [0, threshold_reset], "reset_quota"
            )
        else:
            threshold_upper = threshold_reset >> 16
            threshold_lower = threshold_reset & 0xFFFF
            threshold_lower = threshold_lower - 1 if threshold_lower > 0 else 0
            # reset quota if latency is below threshold
            set_up_queue_report_table_internal(
                [0, threshold_upper - 1], [0, 0xFFFF], "reset_quota"
            )
            set_up_queue_report_table_internal(
                [threshold_upper, threshold_upper], [0, threshold_lower], "reset_quota"
            )

    def set_queue_report_quota(self, port, qid, quota):
        # We are using port[6:0] ++ qid as register index.
        index = (port & 0x7F) << 5 | qid
        self.write_register(
            "FabricEgress.int_egress.queue_report_quota", index, stringify(quota, 2)
        )

    def verify_quota(self, port, qid, quota):
        # We are using port[6:0] ++ qid as register index.
        index = (port & 0x7F) << 5 | qid
        self.verify_register(
            "FabricEgress.int_egress.queue_report_quota", index, stringify(quota, 2)
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
        int_pre_mirrored_packet = self.build_exp_ipv4_unicast_packet(
            pkt,
            next_hop_mac=HOST2_MAC,
            switch_mac=pkt[Ether].dst,
            is_next_hop_spine=is_next_hop_spine,
            tagged2=tagged2,
        )

        # The expected INT report packet
        exp_int_report_pkt_masked = self.build_int_local_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            ig_port,
            eg_port,
            SWITCH_ID,
            int_pre_mirrored_packet,
            is_device_spine,
            send_report_to_spine,
        )

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        # TODO: In these tests, there is only one egress port although the
        # test can generate a report going though the spine and the original
        # packet going to another edge port. port_type programming is
        # always done by using the default value which is PORT_TYPE_EDGE
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

    def runIngressIntDropTest(
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
        drop_reason=INT_DROP_REASON_ACL_DENY,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
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
        int_inner_pkt = pkt.copy()

        # Since we use ingress mirroring for reporting drops by the ingress
        # pipe, the inner pkt will be the same as the ingress one before any
        # header modification (e.g., no MPLS label). However, the egress pipe
        # for INT reports always removes the VLAN header since reports are
        # transmitted over the untagged recirculation port.
        if Dot1Q in int_inner_pkt:
            int_inner_pkt = pkt_remove_vlan(int_inner_pkt)

        # The expected INT report packet
        exp_int_report_pkt_masked = self.build_int_drop_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            ig_port,
            0,  # egress port will be unset
            drop_reason,
            SWITCH_ID,
            int_inner_pkt,
            is_device_spine,
            send_report_to_spine,
            ig_port >> 7,  # hw_id,
            truncate=False,
        )

        install_routing_entry = True
        if drop_reason == INT_DROP_REASON_ACL_DENY:
            self.add_forwarding_acl_drop_ingress_port(ig_port)
        elif drop_reason == INT_DROP_REASON_ROUTING_V4_MISS:
            install_routing_entry = False

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        # TODO: In these tests, there is only one egress port although the
        # test can generate a report going though the spine and the original
        # packet going to another edge port. port_type programming is
        # always done by using the default value which is PORT_TYPE_EDGE
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
            verify_pkt=False,
            install_routing_entry=install_routing_entry,
        )

        if expect_int_report:
            self.verify_packet(exp_int_report_pkt_masked, self.port3)
        self.verify_no_other_packets()

    def runEgressIntDropTest(
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
        drop_reason,
    ):
        """
        Test a packet that is dropped by the egress pipe.
        TODO: currently we only test the case where the packet is dropped by teh egress_vlan
              table.
              We should test cases where the packet is dropped by other tables.
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
        int_pre_mirrored_packet = self.build_exp_ipv4_unicast_packet(
            pkt,
            next_hop_mac=HOST2_MAC,
            switch_mac=pkt[Ether].dst,
            is_next_hop_spine=is_next_hop_spine,
            tagged2=tagged1,  # VLAN tag will be remained since we missed the egress_vlan table
        )

        # The expected INT report packet
        exp_int_report_pkt_masked = self.build_int_drop_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            ig_port,
            eg_port,
            drop_reason,
            SWITCH_ID,
            int_pre_mirrored_packet,
            is_device_spine,
            send_report_to_spine,
            eg_port >> 7,  # hw_id
            truncate=True,
        )

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # IPv4 Routing test

        # If the input pkt has a VLAN tag, use that to configure tables.
        if tagged1 and Dot1Q not in pkt:
            pkt = pkt_add_vlan(pkt, vlan_vid=VLAN_ID_1)

        next_id = 100
        group_id = next_id
        mpls_label = MPLS_LABEL_2
        dst_ipv4 = pkt[IP].dst
        switch_mac = pkt[Ether].dst
        port_type = PORT_TYPE_EDGE
        if is_device_spine:
            port_type = PORT_TYPE_INFRA

        # Setup ports.
        # Note that the "egress_vlan" table is not configured, so packet will be dropped
        # by the egress_vlan table.
        self.set_ingress_port_vlan(
            ig_port, vlan_valid=tagged1, vlan_id=VLAN_ID_1, port_type=port_type
        )

        # Forwarding type -> routing v4
        self.set_forwarding_type(
            ig_port,
            switch_mac,
            ethertype=ETH_TYPE_IPV4,
            fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
        )

        # Routing entry.
        self.add_forwarding_routing_v4_entry(dst_ipv4, 32, next_id)

        if not is_next_hop_spine:
            self.add_next_routing(next_id, eg_port, switch_mac, HOST2_MAC)
            self.add_next_vlan(next_id, VLAN_ID_2)
        else:
            params = [eg_port, switch_mac, HOST2_MAC, mpls_label]
            self.add_next_mpls_and_routing_group(next_id, group_id, [params])
            self.add_next_vlan(next_id, DEFAULT_VLAN)

        self.send_packet(ig_port, pkt)

        if expect_int_report:
            self.verify_packet(exp_int_report_pkt_masked, self.port3)
        self.verify_no_other_packets()

    def runIntQueueTest(
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
        watch_flow=False,
        reset_quota=True,
        threshold_trigger=0,
        threshold_reset=0,
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
        :param watch_flow: install table entry to the watch list table, this will make
                           the pipeline to generate an INT report with both flow and
                           queue flag.
        :reset_quota: resets the queue report quota everytime when we run the test
        "threshold_trigger: the latency threshold to trigger the queue report
        "threshold_reset: the latency threshold to rest the queue report quota
        """
        int_pre_mirrored_packet = self.build_exp_ipv4_unicast_packet(
            pkt,
            next_hop_mac=HOST2_MAC,
            switch_mac=pkt[Ether].dst,
            is_next_hop_spine=is_next_hop_spine,
            tagged2=tagged2,
        )

        # The expected INT report packet
        exp_int_report_pkt_masked = self.build_int_local_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            ig_port,
            eg_port,
            SWITCH_ID,
            int_pre_mirrored_packet,
            is_device_spine,
            send_report_to_spine,
            f_flag=1 if watch_flow else 0,
            q_flag=1,
        )

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(
            is_device_spine, pkt, send_report_to_spine, watch_flow=watch_flow
        )
        # Every packet will always trigger the queue alert
        self.set_up_latency_threshold_for_q_report(threshold_trigger, threshold_reset)
        # Sets the quota for the output port/queue of INT report to zero to make sure
        # we won't keep getting reports for this type of packet.
        self.set_queue_report_quota(port=self.port3, qid=0, quota=0)
        for recirc_port in RECIRCULATE_PORTS:
            self.set_queue_report_quota(port=recirc_port, qid=0, quota=0)
        if reset_quota:
            # To ensure we have enough quota to send a queue report.
            self.set_queue_report_quota(port=eg_port, qid=0, quota=1)

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        # TODO: In these tests, there is only one egress port although the
        # test can generate a report going though the spine and the original
        # packet going to another edge port. port_type programming is
        # always done by using the default value which is PORT_TYPE_EDGE
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
        with_psc,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param with_psc: if the ingress packet should have a PDU Session
               Container (PSC) GTP extension header
        :param is_next_hop_spine: whether the packet should be routed
               to the spines using MPLS SR
        :param is_device_spine: the device is a spine device
        :param send_report_to_spine: if the report is to be forwarded
               to a spine (e.g., collector attached to another leaf)
        """

        # Output packet routed to upstream device.
        exp_pkt = pkt.copy()
        exp_pkt = pkt_route(exp_pkt, HOST2_MAC)
        if not is_next_hop_spine:
            pkt_decrement_ttl(exp_pkt)

        if tagged2:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)

        # Input GTP-encapped packet from eNB.
        gtp_pkt = pkt_add_gtp(
            pkt,
            out_ipv4_src=S1U_ENB_IPV4,
            out_ipv4_dst=S1U_SGW_IPV4,
            teid=UPLINK_TEID,
            ext_psc_type=GTPU_EXT_PSC_TYPE_UL if with_psc else None,
        )

        # Output INT report packet.
        exp_int_report_pkt_masked = self.build_int_local_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            self.port1,
            self.port2,
            SWITCH_ID,
            exp_pkt,
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
        # TODO: In these tests, there is only one egress port although the
        # test can generate a report going though the spine and the original
        # packet going to another edge port. port_type programming is
        # always done by using the default value which is PORT_TYPE_EDGE
        self.runIPv4UnicastTest(
            pkt=gtp_pkt,
            dst_ipv4=pkt[IP].dst,
            exp_pkt=exp_pkt,
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
        with_psc,
        is_next_hop_spine,
        is_device_spine,
        send_report_to_spine,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param with_psc: if the egress packet should have a PDU Session
               Container (PSC) GTP extension header
        :param is_next_hop_spine: whether the packet should be routed
               to the spines using MPLS SR
        :param is_device_spine: the device is a spine device
        :param send_report_to_spine: if the report is to be forwarded
               to a spine (e.g., collector attached to another leaf)
        """
        # Expected GTP-encapped packet.
        exp_pkt = pkt.copy()
        exp_pkt = pkt_route(exp_pkt, HOST2_MAC)
        if not is_next_hop_spine:
            exp_pkt = pkt_decrement_ttl(exp_pkt)

        exp_pkt = pkt_add_gtp(
            exp_pkt,
            out_ipv4_src=S1U_SGW_IPV4,
            out_ipv4_dst=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
            ext_psc_type=GTPU_EXT_PSC_TYPE_DL if with_psc else None,
        )
        if tagged2 and Dot1Q not in exp_pkt:
            exp_pkt = pkt_add_vlan(exp_pkt, VLAN_ID_2)
        if is_next_hop_spine:
            exp_pkt = pkt_add_mpls(exp_pkt, MPLS_LABEL_2, DEFAULT_MPLS_TTL)

        # Expected INT report.
        exp_int_report_pkt_masked = self.build_int_local_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            self.port1,
            self.port2,
            SWITCH_ID,
            exp_pkt,
            is_device_spine,
            send_report_to_spine,
        )

        # Set up entries for downlink.
        self.setup_downlink(
            s1u_sgw_addr=S1U_SGW_IPV4,
            s1u_enb_addr=S1U_ENB_IPV4,
            teid=DOWNLINK_TEID,
            ue_addr=pkt[IP].dst,
            ctr_id=DOWNLINK_PDR_CTR_IDX,
        )

        if with_psc:
            self.enable_encap_with_psc()

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        # TODO: In these tests, there is only one egress port although the
        # test can generate a report going though the spine and the original
        # packet going to another edge port. port_type programming is
        # always done by using the default value which is PORT_TYPE_EDGE
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

    def runUplinkIntDropTest(
        self,
        pkt,
        tagged1,
        tagged2,
        with_psc,
        is_next_hop_spine,
        ig_port,
        eg_port,
        expect_int_report,
        is_device_spine,
        send_report_to_spine,
        drop_reason,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param with_psc: if the egress packet should have a PDU Session
               Container (PSC) GTP extension header
        :param is_next_hop_spine: whether the packet should be routed
               to the spines using MPLS SR
        :param ig_port: the ingress port of the IP unicast packet
        :param eg_port: the egress port of the IP unicast packet
        :param expect_int_report: expected to receive the INT report
        :param is_device_spine: the device is a spine device
        :param send_report_to_spine: if the report is to be forwarded
               to a spine (e.g., collector attached to another leaf)
        """
        gtp_pkt = pkt_add_gtp(
            pkt,
            out_ipv4_src=S1U_ENB_IPV4,
            out_ipv4_dst=S1U_SGW_IPV4,
            teid=UPLINK_TEID,
            ext_psc_type=GTPU_EXT_PSC_TYPE_UL if with_psc else None,
        )

        # Since the packet is dropped by the ingress pipeline and we will never
        # route this packet, the packet will not be changed.
        bridged_packet = pkt.copy()
        if tagged1 and Dot1Q not in bridged_packet:
            bridged_packet = pkt_add_vlan(bridged_packet, VLAN_ID_1)

        # The expected INT report packet
        exp_int_report_pkt_masked = self.build_int_drop_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            ig_port,
            0,  # No egress port set since we drop from ingress pipeline
            drop_reason,
            SWITCH_ID,
            bridged_packet,
            is_device_spine,
            send_report_to_spine,
            eg_port >> 7,  # hw_id,
            truncate=False,  # Never truncated since this is a ingress drop.
        )

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        self.add_s1u_iface(S1U_SGW_IPV4)
        if drop_reason == INT_DROP_REASON_UPLINK_PDR_MISS:
            # Install nothing to pdr nor far table
            pass
        elif drop_reason == INT_DROP_REASON_FAR_MISS:
            self.add_uplink_pdr(
                ctr_id=UPLINK_PDR_CTR_IDX,
                far_id=UPLINK_FAR_ID,
                teid=UPLINK_TEID,
                tunnel_dst_addr=S1U_SGW_IPV4,
            )

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        # TODO: In these tests, there is only one egress port although the
        # test can generate a report going though the spine and the original
        # packet going to another edge port. port_type programming is
        # always done by using the default value which is PORT_TYPE_EDGE
        self.runIPv4UnicastTest(
            pkt=gtp_pkt,
            dst_ipv4=pkt[IP].dst,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            with_another_pkt_later=True,
            ig_port=ig_port,
            eg_port=eg_port,
            verify_pkt=False,
        )

        if expect_int_report:
            self.verify_packet(exp_int_report_pkt_masked, self.port3)
        self.verify_no_other_packets()

    def runDownlinkIntDropTest(
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
        drop_reason,
    ):
        """
        :param pkt: the input packet
        :param tagged1: if the input port should expect VLAN tagged packets
        :param tagged2: if the output port should expect VLAN tagged packets
        :param is_next_hop_spine: whether the packet should be routed
               to the spines using MPLS SR
        :param ig_port: the ingress port of the IP uncast packet
        :param eg_port: the egress port of the IP uncast packet
        :param expect_int_report: expected to receive the INT report
        :param is_device_spine: the device is a spine device
        :param send_report_to_spine: if the report is to be forwarded
               to a spine (e.g., collector attached to another leaf)
        """
        bridged_packet = pkt.copy()
        if tagged1 and Dot1Q not in bridged_packet:
            bridged_packet = pkt_add_vlan(bridged_packet, VLAN_ID_1)

        # The expected INT report packet
        exp_int_report_pkt_masked = self.build_int_drop_report(
            SWITCH_MAC,
            INT_COLLECTOR_MAC,
            SWITCH_IPV4,
            INT_COLLECTOR_IPV4,
            ig_port,
            0,  # No egress port set since we drop from ingress pipeline
            drop_reason,
            SWITCH_ID,
            bridged_packet,
            is_device_spine,
            send_report_to_spine,
            eg_port >> 7,  # hw_id,
            truncate=False,  # Never truncated since this is a ingress drop.
        )

        # Set collector, report table, and mirror sessions
        self.set_up_int_flows(is_device_spine, pkt, send_report_to_spine)

        # Add the UE pool interface and the PDR pointing to the DBUF FAR
        self.add_ue_pool(pkt[IP].dst)
        if drop_reason == INT_DROP_REASON_DOWNLINK_PDR_MISS:
            # Install nothing to pdr nor far table
            pass
        elif drop_reason == INT_DROP_REASON_FAR_MISS:
            self.add_downlink_pdr(
                ctr_id=DOWNLINK_PDR_CTR_IDX, far_id=DOWNLINK_FAR_ID, ue_addr=pkt[IP].dst
            )

        # TODO: Use MPLS test instead of IPv4 test if device is spine.
        # TODO: In these tests, there is only one egress port although the
        # test can generate a report going though the spine and the original
        # packet going to another edge port. port_type programming is
        # always done by using the default value which is PORT_TYPE_EDGE
        self.runIPv4UnicastTest(
            pkt=pkt,
            dst_ipv4=pkt[IP].dst,
            next_hop_mac=HOST2_MAC,
            tagged1=tagged1,
            tagged2=tagged2,
            is_next_hop_spine=is_next_hop_spine,
            prefix_len=32,
            with_another_pkt_later=True,
            ig_port=ig_port,
            eg_port=eg_port,
            verify_pkt=False,
        )

        if expect_int_report:
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
        if not is_bmv2():
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

        if not is_bmv2():
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

        if not is_bmv2():
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


class SlicingTest(FabricTest):
    """Mixin class with methods to manipulate QoS entities
    """

    def add_slice_tc_classifier_entry(
        self, slice_id=None, tc=None, trust_dscp=False, **ftuple
    ):
        if trust_dscp:
            action = "FabricIngress.slice_tc_classifier.trust_dscp"
            params = []
        else:
            action = "FabricIngress.slice_tc_classifier.set_slice_id_tc"
            params = [("slice_id", stringify(slice_id, 1)), ("tc", stringify(tc, 1))]
        self.send_request_add_entry_to_action(
            "FabricIngress.slice_tc_classifier.classifier",
            self.build_acl_matches(**ftuple),
            action,
            params,
            DEFAULT_PRIORITY,
        )

    def configure_slice_tc_meter(self, slice_id, tc, cir, cburst, pir, pburst):
        self.write_indirect_meter(
            m_name="FabricIngress.qos.slice_tc_meter",
            m_index=slice_tc_concat(slice_id, tc),
            cir=cir,
            cburst=cburst,
            pir=pir,
            pburst=pburst,
        )

    def add_queue_entry(self, slice_id, tc, qid=None, color=None):
        slice_tc = slice_tc_concat(slice_id, tc)
        matches = [
            self.Exact("slice_tc", stringify(slice_tc, 1)),
        ]
        if color is not None:
            matches.append(
                self.Ternary("color", stringify(color, 1), stringify(0x3, 1))
            )
        if qid is not None:
            action = "FabricIngress.qos.set_queue"
            action_params = [("qid", stringify(qid, 1))]
        else:
            action = "FabricIngress.qos.meter_drop"
            action_params = []
        self.send_request_add_entry_to_action(
            "FabricIngress.qos.queues",
            matches,
            action,
            action_params,
            DEFAULT_PRIORITY,
        )

    def add_dscp_rewriter_entry(self, eg_port, clear=False):
        self.send_request_add_entry_to_action(
            "FabricEgress.dscp_rewriter.rewriter",
            [self.Exact("eg_port", stringify(eg_port, 2))],
            "FabricEgress.dscp_rewriter." + "clear" if clear else "rewrite",
            [],
        )

    def enable_policing(self, slice_id, tc, color=COLOR_RED):
        self.add_queue_entry(slice_id, tc, None, color=color)


class StatsTest(FabricTest):
    """Mixin class with methods to manipulate stats tables and to verify
    counters.

    Most methods take a generic dictionary 'ftuple', expected to contain
    values for the 5-tuple to match: ipv4_src, ipv4_dst, ip_proto, l4_sport, and
    l4_dport.
    """

    def build_stats_matches(self, gress, stats_flow_id, port, **ftuple):
        port_ = stringify(port, 2)
        stats_flow_id_ = stringify(stats_flow_id, 2)
        if gress == STATS_INGRESS:
            matches = self.build_acl_matches(**ftuple)
            matches.append(self.Exact("ig_port", port_))
        else:
            matches = []
            matches.append(self.Exact("stats_flow_id", stats_flow_id_))
            matches.append(self.Exact("eg_port", port_))
        return matches

    def build_stats_table_entry(self, gress, stats_flow_id, port, **ftuple):
        table_entry = p4runtime_pb2.TableEntry()
        table_name = STATS_TABLE % gress
        table_entry.table_id = self.get_table_id(table_name)
        table_entry.priority = DEFAULT_PRIORITY if gress == STATS_INGRESS else 0
        matches = self.build_stats_matches(
            gress=gress, stats_flow_id=stats_flow_id, port=port, **ftuple
        )
        self.set_match_key(table_entry, table_name, matches)
        return table_entry

    def reset_stats_counter(self, table_entry):
        self.write_direct_counter(table_entry, 0, 0)

    def get_stats_counter(self, gress, stats_flow_id, port, **ftuple):
        # ONOS will read stats counters during flow rule reconciliation. Here we
        # do the same by reading a TableEntry and extracting counter_data
        # (instead of reading DirectCounterEntry).
        req = self.get_new_read_request()
        entity = req.entities.add()
        entity.table_entry.CopyFrom(
            self.build_stats_table_entry(
                gress=gress, stats_flow_id=stats_flow_id, port=port, **ftuple
            )
        )
        entity.table_entry.counter_data.CopyFrom(p4runtime_pb2.CounterData())
        entities = self.read_request(req)
        if len(entities) != 1:
            self.fail("Expected 1 table entry got %d" % len(entities))
        entity = entities.pop()
        if not entity.HasField("table_entry"):
            self.fail("Expected table entry got something else")
        counter_data = entity.table_entry.counter_data
        return counter_data.byte_count, counter_data.packet_count

    def verify_stats_counter(
        self, gress, stats_flow_id, port, byte_count, pkt_count, **ftuple
    ):
        if self.generate_tv:
            # TODO
            return
        actual_byte_count, actual_pkt_count = self.get_stats_counter(
            gress, stats_flow_id, port, **ftuple
        )
        if actual_byte_count != byte_count or actual_pkt_count != pkt_count:
            self.fail(
                "Counter is not same as expected.\
                \nActual packet count: %d, Expected packet count: %d\
                \nActual byte count: %d, Expected byte count: %d\n"
                % (actual_pkt_count, pkt_count, actual_byte_count, byte_count,)
            )

    def add_stats_table_entry(self, gress, stats_flow_id, ports, **ftuple):
        for port in ports:
            matches = self.build_stats_matches(
                gress=gress, stats_flow_id=stats_flow_id, port=port, **ftuple
            )
            if gress == STATS_INGRESS:
                action_param = [("flow_id", stringify(stats_flow_id, 2))]
            else:
                action_param = []
            self.send_request_add_entry_to_action(
                STATS_TABLE % gress,
                matches,
                STATS_ACTION % gress,
                action_param,
                DEFAULT_PRIORITY if gress == STATS_INGRESS else 0,
            )

    def set_up_stats_flows(self, stats_flow_id, ig_port, eg_port, **ftuple):
        self.add_stats_table_entry(
            gress=STATS_INGRESS, stats_flow_id=stats_flow_id, ports=[ig_port], **ftuple
        )
        self.add_stats_table_entry(
            gress=STATS_EGRESS, stats_flow_id=stats_flow_id, ports=[eg_port], **ftuple
        )
        # FIXME: check P4RT spec, are counters reset upon table insert?
        self.reset_stats_counter(
            self.build_stats_table_entry(
                gress=STATS_INGRESS, stats_flow_id=stats_flow_id, port=ig_port, **ftuple
            )
        )
        self.reset_stats_counter(
            self.build_stats_table_entry(
                gress=STATS_EGRESS, stats_flow_id=stats_flow_id, port=eg_port, **ftuple
            )
        )
