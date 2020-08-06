// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __PARSER__
#define __PARSER__

#include "header.p4"
#include "define.p4"

#ifdef WITH_INT
#include "int/data_parser.p4"
#endif // WITH_INT

parser FabricIngressParser (packet_in  packet,
    /* Fabric.p4 */
    out parsed_headers_t               hdr,
    out fabric_ingress_metadata_t      fabric_md,
    /* TNA */
    out ingress_intrinsic_metadata_t   ig_intr_md) {
#ifdef WITH_INT
    IntDataParser() int_data_parser;
#endif
    Checksum() ipv4_checksum;
#ifdef WITH_GTPU
    Checksum() inner_ipv4_checksum;
#endif // WITH_GTPU

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_QINQ: parse_vlan_tag;
            ETHERTYPE_VLAN &&& 0xFEFF: parse_vlan_tag; // 0x8100, 0x9100
            default: parse_untagged_packet;
        }
    }

    state parse_vlan_tag {
        packet.extract(hdr.vlan_tag);
        // Initialize lookup metadata. Packets without a VLAN header will be
        // treated as belonging to a default VLAN ID
        fabric_md.common.vlan_id = hdr.vlan_tag.vlan_id;
        transition select(packet.lookahead<bit<16>>()) {
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
            ETHERTYPE_VLAN: parse_inner_vlan_tag;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
            default: parse_eth_type;
        }
    }

#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
    state parse_inner_vlan_tag {
        packet.extract(hdr.inner_vlan_tag);
        fabric_md.common.inner_vlan_id = hdr.inner_vlan_tag.vlan_id;
        transition parse_eth_type;
    }
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION

    state parse_untagged_packet {
        // Sets default vlan
        fabric_md.common.vlan_id = DEFAULT_VLAN_ID;
        transition parse_eth_type;
    }

    state parse_eth_type {
        packet.extract(hdr.eth_type);
        transition select(hdr.eth_type.value) {
            ETHERTYPE_MPLS: parse_mpls;
            ETHERTYPE_IPV4: parse_non_mpls_headers;
            ETHERTYPE_IPV6: parse_non_mpls_headers;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.mpls);
        fabric_md.common.mpls_label = hdr.mpls.label;
        fabric_md.common.mpls_ttl = hdr.mpls.ttl;
        // There is only one MPLS label for this fabric.
        // Assume header after MPLS header is IPv4/IPv6
        // Lookup first 4 bits for version
        transition select(packet.lookahead<bit<IP_VER_LENGTH>>()) {
            IP_VERSION_4: parse_ipv4;
            IP_VERSION_6: parse_ipv6;
            default: parse_ethernet;
        }
    }

    state parse_non_mpls_headers {
        fabric_md.common.mpls_label = 0;
        fabric_md.common.mpls_ttl = DEFAULT_MPLS_TTL + 1;
        transition select(hdr.eth_type.value) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        fabric_md.ipv4_src_addr = hdr.ipv4.src_addr;
        fabric_md.ipv4_dst_addr = hdr.ipv4.dst_addr;
        fabric_md.common.ip_proto = hdr.ipv4.protocol;
        fabric_md.common.ip_eth_type = ETHERTYPE_IPV4;
        ipv4_checksum.add(hdr.ipv4);
        fabric_md.ipv4_checksum_err = ipv4_checksum.verify();
        // Need header verification?
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        fabric_md.common.ip_proto = hdr.ipv6.next_hdr;
        fabric_md.common.ip_eth_type = ETHERTYPE_IPV6;
        transition select(hdr.ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        fabric_md.common.l4_sport = hdr.tcp.sport;
        fabric_md.common.l4_dport = hdr.tcp.dport;
#ifdef WITH_INT
        transition parse_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_udp {
        packet.extract(hdr.udp);
        fabric_md.common.l4_sport = hdr.udp.sport;
        fabric_md.common.l4_dport = hdr.udp.dport;
        transition select(hdr.udp.dport) {
#ifdef WITH_GTPU
            UDP_PORT_GTPU: parse_gtpu;
#ifdef WITH_INT
            default: parse_int;
#else
            default: accept;
#endif // WITH_INT
#else // WITH_GTPU
#ifdef WITH_INT
            default: parse_int;
#else
            default: accept;
#endif // WITH_INT
#endif // WITH_GTPU
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

#ifdef WITH_INT
    state parse_int {
        transition select(hdr.ipv4.dscp) {
            INT_DSCP &&& INT_DSCP: parse_intl4_shim;
            default: accept;
        }
    }

#ifdef WITH_GTPU
    state parse_inner_int {
        transition select(hdr.inner_ipv4.dscp) {
            INT_DSCP &&& INT_DSCP: parse_intl4_shim;
            default: accept;
        }
    }
#endif

    state parse_intl4_shim {
        packet.extract(hdr.intl4_shim);
        transition parse_int_header;
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }

    state parse_int_data {
        // Parse INT metadata stack, but not tail
        int_data_parser.apply(packet, hdr);
        transition parse_intl4_tail;
    }

    state parse_intl4_tail {
        packet.extract(hdr.intl4_tail);
        transition accept;
    }
#endif // WITH_INT

#ifdef WITH_GTPU
    state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        inner_ipv4_checksum.add(hdr.inner_ipv4);
        fabric_md.inner_ipv4_checksum_err = inner_ipv4_checksum.verify();
        transition select(hdr.inner_ipv4.protocol) {
            PROTO_TCP: parse_inner_tcp;
            PROTO_UDP: parse_inner_udp;
            PROTO_ICMP: parse_inner_icmp;
            default: accept;
        }
    }

    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        fabric_md.common.inner_l4_sport = hdr.inner_tcp.sport;
        fabric_md.common.inner_l4_dport = hdr.inner_tcp.dport;
#ifdef WITH_INT
        transition parse_inner_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        fabric_md.common.inner_l4_sport = hdr.inner_udp.sport;
        fabric_md.common.inner_l4_dport = hdr.inner_udp.dport;
#ifdef WITH_INT
        transition parse_inner_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        transition accept;
    }
#endif // WITH_GTPU
}

control FabricIngressDeparser(packet_out packet,
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    in fabric_ingress_metadata_t fabric_md,
    /* TNA */
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    apply {
        packet.emit(fabric_md.common);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan_tag);
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
        packet.emit(hdr.inner_vlan_tag);
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
        packet.emit(hdr.eth_type);
        packet.emit(hdr.mpls);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
#ifdef WITH_GTPU
        // in case we parsed a GTPU packet but did not decap it
        packet.emit(hdr.gtpu);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.inner_icmp);
#endif // WITH_GTPU
#ifdef WITH_INT
        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
#ifdef WITH_INT_TRANSIT
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_q_congestion);
        packet.emit(hdr.int_egress_tx_util);
#endif // WITH_INT_TRANSIT
#ifndef WITH_INT_SINK // WITHOUT the INT Sink
        packet.emit(hdr.int_data);
#endif // !WITH_INT_SINK
        packet.emit(hdr.intl4_tail);
#endif // WITH_INT
    }
}

parser FabricEgressParser (packet_in packet,
    /* Fabric.p4 */
    out parsed_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {
#ifdef WITH_GTPU
    Checksum() inner_ipv4_checksum;
#endif // WITH_GTPU
#ifdef WITH_INT
    IntDataParser() int_data_parser;
#endif
#ifdef WITH_INT_SINK
    int_mirror_metadata_t int_mirror_md;
#endif

    state start {
        packet.extract(eg_intr_md);
        BridgeMetadataType bridge_md_type = packet.lookahead<BridgeMetadataType>();
        transition select(bridge_md_type) {
            BridgeMetadataType.INGRESS_TO_EGRESS: parse_bridge_metadata;
            BridgeMetadataType.MIRROR_EGRESS_TO_EGRESS: parse_egress_mirror_metadata;
            default: reject;
        }
    }

    state parse_bridge_metadata {
        packet.extract(fabric_md.common);
        transition parse_ethernet;
    }

    state parse_egress_mirror_metadata {
        // TODO: to support different mirror headers
        //       by adding a "mirror_type" field.
#ifdef WITH_INT_SINK
        packet.extract(fabric_md.int_mirror_md);
        fabric_md.common.bridge_md_type = fabric_md.int_mirror_md.bridge_md_type;
        fabric_md.common.vlan_id = DEFAULT_VLAN_ID;

#ifdef WITH_SPGW
        transition select(fabric_md.int_mirror_md.skip_gtpu_headers) {
            1: skip_gtpu_headers_eth;
            default: accept;
        }
#else
        transition accept;
#endif // WITH_SPGW
#else
        transition reject;
#endif // WITH_INT_SINK
    }

#if defined(WITH_SPGW) && defined(WITH_INT_SINK)
    state skip_gtpu_headers_eth {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_VLAN: skip_gtpu_headers_vlan;
            default: skip_gtpu_headers_eth_type;
        }
    }

    state skip_gtpu_headers_vlan {
        packet.extract(hdr.vlan_tag);
        transition skip_gtpu_headers_eth_type;
    }

    state skip_gtpu_headers_eth_type {
        packet.extract(hdr.eth_type);
        transition select(hdr.eth_type.value) {
            ETHERTYPE_MPLS: skip_gtpu_headers_mpls;
            default: skip_gtpu_headers;
        }
    }

    state skip_gtpu_headers_mpls {
        packet.extract(hdr.mpls);
        fabric_md.common.mpls_label = hdr.mpls.label;
        // Add 1 here since the egress next block will decrease
        // the MPLS TTL but we want to leave it unchanged.
        fabric_md.common.mpls_ttl = DEFAULT_MPLS_TTL + 1;
        transition skip_gtpu_headers;
    }

    state skip_gtpu_headers {
        // Skip IP/UDP/GTPU headers: (20 + 8 + 8)*8 bits
        packet.advance(288);
        transition accept;
    }

#endif // defined(WITH_SPGW) && defined(WITH_INT_SINK)

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_QINQ: parse_vlan_tag;
            ETHERTYPE_VLAN &&& 0xFEFF: parse_vlan_tag;
            default: parse_eth_type;
        }
    }

    state parse_vlan_tag {
        packet.extract(hdr.vlan_tag);
        transition select(packet.lookahead<bit<16>>()) {
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
            ETHERTYPE_VLAN: parse_inner_vlan_tag;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
            default: parse_eth_type;
        }
    }

#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
    state parse_inner_vlan_tag {
        packet.extract(hdr.inner_vlan_tag);
        transition parse_eth_type;
    }
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION

    state parse_eth_type {
        packet.extract(hdr.eth_type);
        transition select(hdr.eth_type.value) {
            ETHERTYPE_MPLS: parse_mpls;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.mpls);
        // There is only one MPLS label for this fabric.
        // Assume header after MPLS header is IPv4/IPv6
        // Lookup first 4 bits for version
        transition select(packet.lookahead<bit<IP_VER_LENGTH>>()) {
            IP_VERSION_4: parse_ipv4;
            IP_VERSION_6: parse_ipv6;
            default: parse_ethernet;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        // Need header verification?
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
#ifdef WITH_INT
        transition parse_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dport) {
#ifdef WITH_GTPU
            UDP_PORT_GTPU: parse_gtpu;
#ifdef WITH_INT
            default: parse_int;
#else
            default: accept;
#endif // WITH_INT
#else // WITH_GTPU
#ifdef WITH_INT
            default: parse_int;
#else
            default: accept;
#endif // WITH_INT
#endif // WITH_GTPU
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

#ifdef WITH_INT
    state parse_int {
        transition select(hdr.ipv4.dscp) {
            INT_DSCP &&& INT_DSCP: parse_intl4_shim;
            default: accept;
        }
    }

#ifdef WITH_GTPU
    state parse_inner_int {
        transition select(hdr.inner_ipv4.dscp) {
            INT_DSCP &&& INT_DSCP: parse_intl4_shim;
            default: accept;
        }
    }
#endif // WITH_GTPU

    state parse_intl4_shim {
        packet.extract(hdr.intl4_shim);
        transition parse_int_header;
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }

    state parse_int_data {
        // Parse INT metadata stack, but not tail
        int_data_parser.apply(packet, hdr);
        transition parse_intl4_tail;
    }

    state parse_intl4_tail {
        packet.extract(hdr.intl4_tail);
        transition accept;
    }
#endif // WITH_INT

#ifdef WITH_GTPU
    state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        inner_ipv4_checksum.add(hdr.inner_ipv4);
        fabric_md.inner_ipv4_checksum_err = inner_ipv4_checksum.verify();
        transition select(hdr.inner_ipv4.protocol) {
            PROTO_TCP: parse_inner_tcp;
            PROTO_UDP: parse_inner_udp;
            PROTO_ICMP: parse_inner_icmp;
            default: accept;
        }
    }

    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
#ifdef WITH_INT
        transition parse_inner_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
#ifdef WITH_INT
        transition parse_inner_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        transition accept;
    }
#endif // WITH_GTPU
}

control FabricEgressMirror(
    in parsed_headers_t hdr,
    in fabric_egress_metadata_t fabric_md) {
    Mirror() mirror;
    apply {
#ifdef WITH_INT_SINK
        if (fabric_md.int_mirror_md.isValid()) {
            mirror.emit<int_mirror_metadata_t>(fabric_md.int_mirror_md.mirror_session_id,
                                               fabric_md.int_mirror_md);
        }
#endif // WITH_INT_SINK
    }
}

control FabricEgressDeparser(packet_out packet,
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    in fabric_egress_metadata_t fabric_md,
    /* TNA */
    in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    Checksum() ipv4_checksum;
    FabricEgressMirror() egress_mirror;
#ifdef WITH_GTPU
    Checksum() outer_ipv4_checksum;
#endif // WITH_GTPU

    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        // TODO: update TCP/UDP checksum
#ifdef WITH_GTPU
        if (hdr.outer_ipv4.isValid()) {
            hdr.outer_ipv4.hdr_checksum = outer_ipv4_checksum.update({
                hdr.outer_ipv4.version,
                hdr.outer_ipv4.ihl,
                hdr.outer_ipv4.dscp,
                hdr.outer_ipv4.ecn,
                hdr.outer_ipv4.total_len,
                hdr.outer_ipv4.identification,
                hdr.outer_ipv4.flags,
                hdr.outer_ipv4.frag_offset,
                hdr.outer_ipv4.ttl,
                hdr.outer_ipv4.protocol,
                hdr.outer_ipv4.src_addr,
                hdr.outer_ipv4.dst_addr
            });
        }
#endif // WITH_GTPU
#ifdef WITH_INT_SINK
        if (hdr.report_ipv4.isValid()) {
            hdr.report_ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.report_ipv4.version,
                hdr.report_ipv4.ihl,
                hdr.report_ipv4.dscp,
                hdr.report_ipv4.ecn,
                hdr.report_ipv4.total_len,
                hdr.report_ipv4.identification,
                hdr.report_ipv4.flags,
                hdr.report_ipv4.frag_offset,
                hdr.report_ipv4.ttl,
                hdr.report_ipv4.protocol,
                hdr.report_ipv4.src_addr,
                hdr.report_ipv4.dst_addr
            });
        }
#endif // WITH_INT_SINK
        egress_mirror.apply(hdr, fabric_md);
        packet.emit(hdr.packet_in);
#ifdef WITH_INT_SINK
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_eth_type);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_fixed_header);
        packet.emit(hdr.local_report_header);
#endif // WITH_INT_SINK
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan_tag);
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
        packet.emit(hdr.inner_vlan_tag);
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
        packet.emit(hdr.eth_type);
        packet.emit(hdr.mpls);
#ifdef WITH_GTPU
        packet.emit(hdr.outer_ipv4);
        packet.emit(hdr.outer_udp);
        packet.emit(hdr.outer_gtpu);
#endif // WITH_GTPU
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
#ifdef WITH_GTPU
        // in case we parsed a GTPU packet but did not decap it
        // these should never happen at the same time as the outer GTPU tunnel headers
        packet.emit(hdr.gtpu);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.inner_icmp);
#endif // WITH_GTPU
#ifdef WITH_INT
        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
#ifdef WITH_INT_TRANSIT
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_q_congestion);
        packet.emit(hdr.int_egress_tx_util);
#endif // WITH_INT_TRANSIT
#ifndef WITH_INT_SINK // WITHOUT the INT Sink
        packet.emit(hdr.int_data);
#endif // !WITH_INT_SINK
        packet.emit(hdr.intl4_tail);
#endif // defined(WITH_INT_TRANSIT) || defined(WITH_INT_SOURCE)
    }
}

#endif
