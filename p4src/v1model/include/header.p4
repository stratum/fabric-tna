// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __HEADER__
#define __HEADER__

#include "define.p4"


@controller_header("packet_in")
header packet_in_header_t {
    PortId_t ingress_port;
    bit<7>   _pad0;
}

// This header must have a pseudo ethertype at offset 12, to be parseable as an
// Ethernet frame in the ingress parser.
@controller_header("packet_out")
header packet_out_header_t {
    @padding bit<7>   pad0;
    PortId_t          egress_port;
    @padding bit<3>   pad1;
    QueueId_t         queue_id;
    @padding bit<5>   pad2;
    CpuLoopbackMode_t cpu_loopback_mode; // FIXME Can I treat this as bit<2>? take a look at define.p4;
                                         // this way I could try to use this same header in V1model.
    bit<1>            do_forwarding;
    @padding bit<16>  pad3;
    @padding bit<48>  pad4;
    bit<16>           ether_type;
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
    mpls_label_t label;
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
    // Not matched/modified. Treat as payload.
    // bit<32> seq_no;
    // bit<32> ack_no;
    // bit<4>  data_offset;
    // bit<3>  res;
    // bit<3>  ecn;
    // bit<6>  ctrl;
    // bit<16> window;
    // bit<16> checksum;
    // bit<16> urgent_ptr;
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
    // Not matched/modified. Treat as payload.
    // bit<16> checksum;
    // Other optional fields...
}

header vxlan_t {
    bit<8>  flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8>  reserved_2;
}

// Used for table lookup. Initialized with the parsed headers, or 0 if invalid
// to avoid unexpected match behavior due to PHV overlay. Never updated by the
// pipe. When both outer and inner IPv4 headers are valid, this should always
// carry the inner ones. The assumption is that we terminate GTP tunnels in the
// fabric, so we are more interested in observing/blocking the inner flows. We
// might revisit this decision in the future.
struct lookup_metadata_t {
    mac_addr_t              eth_dst;
    mac_addr_t              eth_src;
    bit<16>                 eth_type;
    vlan_id_t               vlan_id;
    bool                    is_ipv4;
    bit<32>                 ipv4_src;
    bit<32>                 ipv4_dst;
    bit<8>                  ip_proto;
    l4_port_t               l4_sport;
    l4_port_t               l4_dport;
    bit<8>                  icmp_type;
    bit<8>                  icmp_code;
}

// Used for holding basic mirror information.
// When mirroring, the egress parser will see two types of packets: one with
// bridged.bmd_type and another with mirror.bmd_type.
struct common_mirror_metadata_t {
    MirrorId_t         mirror_session_id;
    //BridgedMdType_t    bmd_type;
}


struct fabric_ingress_metadata_t {
    flow_hash_t              ecmp_hash;
    lookup_metadata_t        lkp;
    bit<32>                  routing_ipv4_dst; // Outermost
    bool                     skip_forwarding;
    bool                     skip_next;
    next_id_t                next_id;
    bool                     egress_port_set;
    bool                     punt_to_cpu;
    // FIXME: checksum errors are set but never read, remove or test it
    bool                     ipv4_checksum_err;
    bool                     inner_ipv4_checksum_err;
    PortType_t               ig_port_type;
    common_mirror_metadata_t mirror;
}

header fake_ethernet_t {
    @padding bit<48> _pad0;
    @padding bit<48> _pad1;
    bit<16> ether_type;
}

struct ingress_headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    fake_ethernet_t fake_ethernet;
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
    eth_type_t eth_type;
    mpls_t mpls;
    ipv4_t ipv4;
    ipv6_t ipv6;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    vxlan_t vxlan;
    ethernet_t inner_ethernet;
    eth_type_t inner_eth_type;
    ipv4_t inner_ipv4;
    tcp_t inner_tcp;
    udp_t inner_udp;
    icmp_t inner_icmp;
}

#endif // __HEADER__
