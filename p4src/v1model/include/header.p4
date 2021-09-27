// Copyright 2021-present Open Networking Foundation
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
    CpuLoopbackMode_t cpu_loopback_mode;
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


struct fabric_ingress_metadata_t {
    PortType_t               ig_port_type;
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
    ipv4_t ipv4;
}

#endif // __HEADER__
