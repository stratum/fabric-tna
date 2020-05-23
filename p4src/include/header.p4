// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __HEADER__
#define __HEADER__

#include "define.p4"

@controller_header("packet_in")
header packet_in_header_t {
    PortId_t ingress_port;
    bit<7> _pad;
}

@controller_header("packet_out")
header packet_out_header_t {
    PortId_t egress_port;
    bit<7> _pad;
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

// Custom metadata definition
header ip_metadata_t {
    bit<16> ip_eth_type;
    bit<8>  ip_proto;
    bool    ipv4_checksum_err;
    @padding bit<7> padding;
}
@flexible
@pa_auto_init_metadata
header vlan_metadata_t {
    vlan_id_t       vlan_id;
    bit<3>          vlan_pri;
    bit<1>          vlan_cfi;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
    vlan_id_t       inner_vlan_id;
    bit<3>          inner_vlan_pri;
    bit<1>          inner_vlan_cfi;
#endif // WITH_DOUBLE_VLAN_TERMINATION
}
@pa_auto_init_metadata
@pa_container_size("ingress", "fabric_metadata.mpls.mpls_label", 32)
header mpls_metadata_t {
    mpls_label_t    mpls_label;
    @padding bit<4> padding;
    bit<8>          mpls_ttl;
}
header l4_metadata_t {
    bit<16>       l4_sport;
    bit<16>       l4_dport;
}
@pa_container_size("egress", "fabric_metadata.ctrl.ingress_port", 16)
@pa_auto_init_metadata
header control_metadata_t {
    bool            skip_forwarding;
    bool            skip_next;
    fwd_type_t      fwd_type;
    next_id_t       next_id;
    bool            is_multicast;
    bool            push_double_vlan;
    bool            is_mirror;
    MirrorId_t      mirror_id;
    @padding bit<5> padding;
    PortId_t        ingress_port;
}
struct fabric_metadata_t {
    vlan_metadata_t vlan;
    mpls_metadata_t mpls;
    ip_metadata_t ip;
    l4_metadata_t l4;
    control_metadata_t ctrl;
}

struct parsed_headers_t {
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
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

#endif
