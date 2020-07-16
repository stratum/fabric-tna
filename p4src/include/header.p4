// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __HEADER__
#define __HEADER__

#include "define.p4"

@controller_header("packet_in")
header packet_in_header_t {
    bit<16> ingress_port;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<16> egress_port;
}

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
}

// NOTE: splitting the eth_type from the ethernet header helps to match on
//  the actual eth_type without checking validity bit of the VLAN tags.
header eth_type_t {
    bit<16> value;
}

header vlan_tag_t {
    bit<16> eth_type;
    bit<3> pri;
    bit<1> cfi;
    vlan_id_t vlan_id;
}

header mpls_t {
    bit<20> label;
    bit<3> tc;
    bit<1> bos;
    bit<8> ttl;
}

header pppoe_t {
    bit<4>  version;
    bit<4>  type_id;
    bit<8>  code;
    bit<16> session_id;
    bit<16> length;
    bit<16> protocol;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

#ifdef WITH_SPGW
// GTPU v1
header gtpu_t {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* next extension hdr present? */
    bit<1>  seq_flag;   /* sequence no. */
    bit<1>  npdu_flag;  /* n-pdn number present ? */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    teid_t  teid;       /* tunnel endpoint id */
}
#endif // WITH_SPGW

// Custom metadata definition
@flexible
@pa_auto_init_metadata
struct fabric_ingress_metadata_t {
    bit<32>         ipv4_src_addr;
    bit<32>         ipv4_dst_addr;
    vlan_id_t       vlan_id;
    bit<3>          vlan_pri;
    bit<1>          vlan_cfi;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
    bool            push_double_vlan;
    vlan_id_t       inner_vlan_id;
    bit<3>          inner_vlan_pri;
    bit<1>          inner_vlan_cfi;
#endif // WITH_DOUBLE_VLAN_TERMINATION
    bit<16> ip_eth_type;
    bit<8>  ip_proto;
    bool    ipv4_checksum_err;
    mpls_label_t    mpls_label;
    bit<8>          mpls_ttl;
    bit<16>         l4_sport;
    bit<16>         l4_dport;
    bool            skip_forwarding;
    bool            skip_next;
    fwd_type_t      fwd_type;
    next_id_t       next_id;
    bool            is_multicast;
    bool            is_mirror;
    MirrorId_t      mirror_id;
#ifdef WITH_SPGW
    bit<16>         inner_l4_sport;
    bit<16>         inner_l4_dport;
    bool            needs_gtpu_encap;
    bool            needs_gtpu_decap;
    bool            pdr_hit;
    bool            far_dropped;
    bool            notify_spgwc;
    bool            skip_spgw;
    far_id_t        far_id;
    teid_t          gtpu_teid;
    bit<32>         gtpu_tunnel_sip;
    bit<32>         gtpu_tunnel_dip;
    bit<16>         gtpu_tunnel_sport;
    pdr_ctr_id_t    pdr_ctr_id;
    SpgwInterface   spgw_src_iface;
    SpgwDirection   spgw_direction;
#endif // WITH_SPGW
}

@flexible
@pa_auto_init_metadata
struct fabric_egress_metadata_t {
    bool            is_multicast;
    PortId_t        ingress_port;
    vlan_id_t       vlan_id;
    mpls_label_t    mpls_label;
    bit<8>          mpls_ttl;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
    bool            push_double_vlan;
    vlan_id_t       inner_vlan_id;
#endif // WITH_DOUBLE_VLAN_TERMINATION
    bit<16>         ip_eth_type;
    bit<8>          ip_proto;
#ifdef WITH_SPGW
    teid_t          gtpu_teid;
    bit<32>         gtpu_tunnel_sip;
    bit<32>         gtpu_tunnel_dip;
    bit<16>         gtpu_tunnel_sport;
    pdr_ctr_id_t    pdr_ctr_id;
#endif // WITH_SPGW
}

@flexible
header bridge_metadata_t {
    mpls_label_t    mpls_label;
    bit<8>          mpls_ttl;
    bool            is_multicast;
    PortId_t        ingress_port;
    vlan_id_t       vlan_id;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
    bool            push_double_vlan;
    vlan_id_t       inner_vlan_id;
#endif // WITH_DOUBLE_VLAN_TERMINATION
    bit<16>         ip_eth_type;
    bit<8>          ip_proto;
#ifdef WITH_SPGW
    bool            gtpu_needs_encap;
    teid_t          gtpu_teid;
    bit<32>         gtpu_tunnel_sip;
    bit<32>         gtpu_tunnel_dip;
    bit<16>         gtpu_tunnel_sport;
    pdr_ctr_id_t    pdr_ctr_id;
#endif // WITH_SPGW
}

struct parsed_headers_t {
    bridge_metadata_t bridge_md;
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
    vlan_tag_t inner_vlan_tag;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
    eth_type_t eth_type;
    mpls_t mpls;
    ipv4_t ipv4;
    ipv6_t ipv6;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
#ifdef WITH_SPGW
    ipv4_t outer_ipv4;
    udp_t outer_udp;
    gtpu_t gtpu;
    tcp_t inner_tcp;
    udp_t inner_udp;
    icmp_t inner_icmp;
#endif // WITH_SPGW
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

#endif
