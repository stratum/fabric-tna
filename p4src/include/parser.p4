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
        hdr.bridge_md.ig_tstamp = ig_intr_md.ingress_mac_tstamp;
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
            ETHERTYPE_QINQ_NON_STD: parse_vlan_tag;
            ETHERTYPE_VLAN: parse_vlan_tag;
            default: parse_untagged_packet;
        }
    }

    state parse_vlan_tag {
        packet.extract(hdr.vlan_tag);
        // Initialize lookup metadata. Packets without a VLAN header will be
        // treated as belonging to a default VLAN ID
        fabric_md.vlan_id = hdr.vlan_tag.vlan_id;
        fabric_md.vlan_pri = hdr.vlan_tag.pri;
        fabric_md.vlan_cfi = hdr.vlan_tag.cfi;
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
        fabric_md.inner_vlan_id = hdr.inner_vlan_tag.vlan_id;
        fabric_md.inner_vlan_pri = hdr.inner_vlan_tag.pri;
        fabric_md.inner_vlan_cfi = hdr.inner_vlan_tag.cfi;
        transition parse_eth_type;
    }
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION

    state parse_untagged_packet {
        // Sets default vlan
        fabric_md.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.vlan_pri = 3w0;
        fabric_md.vlan_cfi = 1w0;
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
        fabric_md.mpls_label = hdr.mpls.label;
        fabric_md.mpls_ttl = hdr.mpls.ttl;
        // There is only one MPLS label for this fabric.
        // Assume header after MPLS header is IPv4/IPv6
        // Lookup first 4 bits for version
        transition select(packet.lookahead<bit<IP_VER_LENGTH>>()) {
            // The packet should be either IPv4 or IPv6.
            // If we have MPLS, go directly to parsing state without
            // moving to pre_ states, the packet is considered MPLS
            IP_VERSION_4: parse_ipv4;
            IP_VERSION_6: parse_ipv6;
            default: parse_ethernet;
        }
    }

    state parse_non_mpls_headers {
        // Packets with a valid MPLS header will have
        // fabric_md.mpls_ttl set to the packet's MPLS ttl value (see
        // parser). In any case, if we are forwarding via MPLS, ttl will be
        // decremented in egress.
        fabric_md.mpls_ttl = DEFAULT_MPLS_TTL + 1;
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
        fabric_md.ip_proto = hdr.ipv4.protocol;
        fabric_md.ip_eth_type = ETHERTYPE_IPV4;
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
        fabric_md.ip_proto = hdr.ipv6.next_hdr;
        fabric_md.ip_eth_type = ETHERTYPE_IPV6;
        transition select(hdr.ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        fabric_md.l4_sport = hdr.tcp.sport;
        fabric_md.l4_dport = hdr.tcp.dport;
#ifdef WITH_INT
        transition parse_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_udp {
        packet.extract(hdr.udp);
        fabric_md.l4_sport = hdr.udp.sport;
        fabric_md.l4_dport = hdr.udp.dport;
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
        fabric_md.inner_l4_sport = hdr.inner_tcp.sport;
        fabric_md.inner_l4_dport = hdr.inner_tcp.dport;
#ifdef WITH_INT
        transition parse_inner_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        fabric_md.inner_l4_sport = hdr.inner_udp.sport;
        fabric_md.inner_l4_dport = hdr.inner_udp.dport;
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
        packet.emit(hdr.bridge_md);
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
    bridge_metadata_t bridge_md;

    state start {
        packet.extract(eg_intr_md);
        transition parse_bridge_metadata;
    }

    state parse_bridge_metadata {
        packet.extract(bridge_md);
        fabric_md.vlan_id = bridge_md.vlan_id;
        fabric_md.mirror_session_id = MIRROR_SESSION_ID_INVALID;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
        fabric_md.push_double_vlan = bridge_md.push_double_vlan;
        fabric_md.inner_vlan_id = bridge_md.inner_vlan_id;
#endif // WITH_DOUBLE_VLAN_TERMINATION
#ifdef WITH_GTPU
        fabric_md.spgw_ipv4_len = bridge_md.spgw_ipv4_len;
        fabric_md.needs_gtpu_encap = bridge_md.needs_gtpu_encap;
        fabric_md.skip_spgw = bridge_md.skip_spgw;
        fabric_md.gtpu_teid = bridge_md.gtpu_teid;
        fabric_md.gtpu_tunnel_sip = bridge_md.gtpu_tunnel_sip;
        fabric_md.gtpu_tunnel_dip = bridge_md.gtpu_tunnel_dip;
        fabric_md.gtpu_tunnel_sport = bridge_md.gtpu_tunnel_sport;
        fabric_md.pdr_ctr_id = bridge_md.pdr_ctr_id;
#endif // WITH_GTPU
        fabric_md.ip_eth_type = bridge_md.ip_eth_type;
        fabric_md.ip_proto = bridge_md.ip_proto;
        fabric_md.mpls_label = bridge_md.mpls_label;
        fabric_md.mpls_ttl = bridge_md.mpls_ttl;
        fabric_md.is_multicast = bridge_md.is_multicast;
        fabric_md.ingress_port = bridge_md.ingress_port;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_QINQ: parse_vlan_tag;
            ETHERTYPE_QINQ_NON_STD: parse_vlan_tag;
            ETHERTYPE_VLAN: parse_vlan_tag;
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
            // The packet should be either IPv4 or IPv6.
            // If we have MPLS, go directly to parsing state without
            // moving to pre_ states, the packet is considered MPLS
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
        fabric_md.l4_sport = hdr.tcp.sport;
        fabric_md.l4_dport = hdr.tcp.dport;
#ifdef WITH_INT
        transition parse_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_udp {
        packet.extract(hdr.udp);
        fabric_md.l4_sport = hdr.udp.sport;
        fabric_md.l4_dport = hdr.udp.dport;
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
        fabric_md.l4_sport = 0; // Invalid
        fabric_md.l4_dport = 0; // Invalid
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
        fabric_md.inner_l4_sport = hdr.inner_tcp.sport;
        fabric_md.inner_l4_dport = hdr.inner_tcp.dport;
#ifdef WITH_INT
        transition parse_inner_int;
#else
        transition accept;
#endif // WITH_INT
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        fabric_md.inner_l4_sport = hdr.inner_udp.sport;
        fabric_md.inner_l4_dport = hdr.inner_udp.dport;
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
        if (fabric_md.mirror_session_id == MIRROR_SESSION_ID_INT_REPORT) {
            mirror.emit<int_mirror_metadata_t>(fabric_md.mirror_session_id, {
                fabric_md.bridge_md_type,
                fabric_md.int_len_words,
                fabric_md.int_switch_id,
                fabric_md.int_hop_latency,
                fabric_md.int_q_id,
                fabric_md.int_q_occupancy,
                fabric_md.int_ingress_tstamp,
                fabric_md.int_egress_tstamp
                // FIXME: include all INT metadata from previous node.
            });
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
        egress_mirror.apply(hdr, fabric_md);
        packet.emit(hdr.packet_in);
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
        packet.emit(hdr.gtpu);
#endif // WITH_GTPU
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);

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
