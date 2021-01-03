// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __PARSER__
#define __PARSER__

#include "header.p4"
#include "define.p4"

parser FabricIngressParser (packet_in  packet,
    /* Fabric.p4 */
    out parsed_headers_t               hdr,
    out fabric_ingress_metadata_t      fabric_md,
    /* TNA */
    out ingress_intrinsic_metadata_t   ig_intr_md) {
    Checksum() ipv4_checksum;
#ifdef WITH_SPGW
    Checksum() inner_ipv4_checksum;
#endif // WITH_SPGW

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        fabric_md.bridged.setValid();
        fabric_md.bridged.bridge_type = BridgeType_t.INGRESS_TO_EGRESS;
        fabric_md.bridged.ig_port = ig_intr_md.ingress_port;
        fabric_md.bridged.ig_tstamp = ig_intr_md.ingress_mac_tstamp;
        transition check_ethernet;
    }

    state check_ethernet {
        // We use ethernet-like headers to signal the presence of custom
        // metadata before the actual ethernet frame.
        fake_ethernet_t tmp = packet.lookahead<fake_ethernet_t>();
        transition select(tmp.ether_type) {
            ETHERTYPE_CPU_LOOPBACK_INGRESS: parse_fake_ethernet;
            ETHERTYPE_CPU_LOOPBACK_EGRESS: parse_fake_ethernet_and_accept;
            ETHERTYPE_PACKET_OUT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_fake_ethernet {
        packet.extract(hdr.fake_ethernet);
        transition parse_ethernet;
    }

    state parse_fake_ethernet_and_accept {
        packet.extract(hdr.fake_ethernet);
        // Will punt to CPU as-is. No need to parse further.
        transition accept;
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        // Will send to requested egress port as-is. No need to parse further.
        transition accept;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_QINQ: parse_vlan_tag;
            ETHERTYPE_VLAN &&& 0xFEFF: parse_vlan_tag; // 0x8100, 0x9100
            default: parse_untagged;
        }
    }

    state parse_vlan_tag {
        packet.extract(hdr.vlan_tag);
        // Initialize lookup metadata. Packets without a VLAN header will be
        // treated as belonging to a default VLAN ID
        fabric_md.bridged.vlan_id = hdr.vlan_tag.vlan_id;
        // fabric_md.bridged.vlan_cfi = hdr.vlan_tag.cfi;
        // fabric_md.bridged.vlan_pri = hdr.vlan_tag.pri;
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
        fabric_md.bridged.inner_vlan_id = hdr.inner_vlan_tag.vlan_id;
        // fabric_md.bridged.inner_vlan_cfi = hdr.inner_vlan_tag.cfi;
        // fabric_md.bridged.inner_vlan_pri = hdr.inner_vlan_tag.pri;
        transition parse_eth_type;
    }
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION

    state parse_untagged {
        // Sets default vlan
        fabric_md.bridged.vlan_id = DEFAULT_VLAN_ID;
        // fabric_md.bridged.vlan_cfi = 3w0;
        // fabric_md.bridged.vlan_pri = 1w0;
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
        fabric_md.bridged.mpls_label = hdr.mpls.label;
        fabric_md.bridged.mpls_ttl = hdr.mpls.ttl;
        // There is only one MPLS label for this fabric.
        // Assume header after MPLS header is IPv4/IPv6
        // Lookup first 4 bits for version
        transition select(packet.lookahead<bit<IP_VER_BITS>>()) {
            IP_VERSION_4: parse_ipv4;
            IP_VERSION_6: parse_ipv6;
            default: reject;
        }
    }

    state parse_non_mpls_headers {
        fabric_md.bridged.mpls_label = 0;
        fabric_md.bridged.mpls_ttl = DEFAULT_MPLS_TTL + 1;
        transition select(hdr.eth_type.value) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        fabric_md.ipv4_src = hdr.ipv4.src_addr;
        fabric_md.ipv4_dst = hdr.ipv4.dst_addr;
        fabric_md.bridged.ip_proto = hdr.ipv4.protocol;
        fabric_md.bridged.ip_eth_type = ETHERTYPE_IPV4;
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
        fabric_md.bridged.ip_proto = hdr.ipv6.next_hdr;
        fabric_md.bridged.ip_eth_type = ETHERTYPE_IPV6;
        transition select(hdr.ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        fabric_md.bridged.l4_sport = hdr.tcp.sport;
        fabric_md.bridged.l4_dport = hdr.tcp.dport;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        fabric_md.bridged.l4_sport = hdr.udp.sport;
        fabric_md.bridged.l4_dport = hdr.udp.dport;
        transition select(hdr.udp.dport) {
#ifdef WITH_SPGW
            UDP_PORT_GTPU: parse_gtpu;
#endif // WITH_SPGW
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

#ifdef WITH_SPGW
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
        fabric_md.bridged.inner_l4_sport = hdr.inner_tcp.sport;
        fabric_md.bridged.inner_l4_dport = hdr.inner_tcp.dport;
        transition accept;
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        fabric_md.bridged.inner_l4_sport = hdr.inner_udp.sport;
        fabric_md.bridged.inner_l4_dport = hdr.inner_udp.dport;
        transition accept;
    }

    state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        transition accept;
    }
#endif // WITH_SPGW
}

control FabricIngressDeparser(packet_out packet,
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    in fabric_ingress_metadata_t fabric_md,
    /* TNA */
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    apply {
        packet.emit(fabric_md.bridged);
        packet.emit(hdr.fake_ethernet);
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan_tag);
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
        packet.emit(hdr.inner_vlan_tag);
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
        packet.emit(hdr.eth_type);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
#ifdef WITH_SPGW
        // in case we parsed a GTPU packet but did not decap it
        packet.emit(hdr.gtpu);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.inner_icmp);
#endif // WITH_SPGW
    }
}

parser FabricEgressParser (packet_in packet,
    /* Fabric.p4 */
    out parsed_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {
#ifdef WITH_SPGW
    Checksum() inner_ipv4_checksum;
#endif // WITH_SPGW

    state start {
        packet.extract(eg_intr_md);
        fabric_md.cpu_port = 0;
        common_egress_metadata_t common_eg_md = packet.lookahead<common_egress_metadata_t>();
        transition select(common_eg_md.bridge_type, common_eg_md.mirror_type) {
            (BridgeType_t.INGRESS_TO_EGRESS, _): parse_bridged_md;
#ifdef WITH_INT
            (BridgeType_t.EGRESS_MIRROR,  MirrorType_t.INT_LOCAL_REPORT): parse_int_report_mirror;
#endif // WITH_INT
            default: reject;
        }
    }

    state parse_bridged_md {
        packet.extract(fabric_md.bridged);
#ifdef WITH_INT
        fabric_md.int_mirror.setValid();
        fabric_md.int_mirror.strip_gtpu = 0;
#endif // WITH_INT
        transition check_ethernet;
    }

#ifdef WITH_INT
    state parse_int_report_mirror {
        packet.extract(fabric_md.int_mirror);
        fabric_md.bridged.bridge_type = fabric_md.int_mirror.bridge_type;
        fabric_md.bridged.vlan_id = DEFAULT_VLAN_ID;
        transition check_ethernet;
    }
#endif // WITH_INT

    state check_ethernet {
        fake_ethernet_t tmp = packet.lookahead<fake_ethernet_t>();
        transition select(tmp.ether_type) {
            ETHERTYPE_CPU_LOOPBACK_INGRESS: set_cpu_loopback_egress;
            ETHERTYPE_CPU_LOOPBACK_EGRESS: reject;
            default: parse_ethernet;
        }
    }

    state set_cpu_loopback_egress {
        hdr.fake_ethernet.setValid();
        hdr.fake_ethernet.ether_type = ETHERTYPE_CPU_LOOPBACK_EGRESS;
        packet.advance(ETH_HDR_BYTES * 8);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_QINQ: parse_vlan_tag;
            ETHERTYPE_VLAN &&& 0xFEFF: parse_vlan_tag;
            default: check_eth_type;
        }
    }

    state parse_vlan_tag {
        packet.extract(hdr.vlan_tag);
        transition select(packet.lookahead<bit<16>>()) {
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
            ETHERTYPE_VLAN: parse_inner_vlan_tag;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
            default: check_eth_type;
        }
    }

#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
    state parse_inner_vlan_tag {
        packet.extract(hdr.inner_vlan_tag);
        transition check_eth_type;
    }
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION

    state check_eth_type {
        transition select(packet.lookahead<bit<(ETH_TYPE_BYTES * 8)>>()) {
            ETHERTYPE_MPLS: strip_mpls;
            ETHERTYPE_IPV4: parse_eth_type;
            ETHERTYPE_IPV6: parse_eth_type;
        }
    }

    // We expect MPLS to be present only for egress-to-egress clones for INT
    // reporting, in which case we need to remove the MPLS header as not
    // supported by the collector. For all other cases, the MPLS label is
    // always popped in ingress and pushed again in egress (if present in
    // bridged metadata).
    state strip_mpls {
        fabric_md.mpls_stripped = 1;
        packet.advance((ETH_TYPE_BYTES + MPLS_HDR_BYTES) * 8);
        transition select(packet.lookahead<bit<IP_VER_BITS>>()) {
            IP_VERSION_4: strip_mpls_ipv4;
            IP_VERSION_6: strip_mpls_ipv6;
            default: reject;
        }
    }

    state strip_mpls_ipv4 {
        hdr.eth_type.setValid();
        hdr.eth_type.value = ETHERTYPE_IPV4;
        transition check_ipv4;
    }

    state strip_mpls_ipv6 {
        hdr.eth_type.setValid();
        hdr.eth_type.value = ETHERTYPE_IPV6;
        transition parse_ipv6;
    }

    state parse_eth_type {
        packet.extract(hdr.eth_type);
        fabric_md.mpls_stripped = 0;
        transition select(hdr.eth_type.value) {
            ETHERTYPE_IPV4: check_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state check_ipv4 {
#if defined(WITH_INT) && defined(WITH_SPGW)
        transition select(fabric_md.int_mirror.strip_gtpu) {
            0: parse_ipv4;
            1: strip_gtpu_and_accept;
        }
#else
        transition parse_ipv4;
#endif // defined(WITH_INT) && defined(WITH_SPGW)
    }

#if defined(WITH_INT) && defined(WITH_SPGW)
    // We strip the GTP-U header because we want the INT collector to track
    // the inner flow.
    state strip_gtpu_and_accept {
        packet.advance((IPV4_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES) * 8);
        transition accept;
    }
#endif // defined(WITH_INT) && defined(WITH_SPGW)

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
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dport) {
#ifdef WITH_SPGW
            UDP_PORT_GTPU: parse_gtpu;
#endif // WITH_SPGW
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

#ifdef WITH_SPGW
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
        transition accept;
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }

    state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        transition accept;
    }
#endif // WITH_SPGW
}

control FabricEgressMirror(
    in parsed_headers_t hdr,
    in fabric_egress_metadata_t fabric_md,
    in egress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
    Mirror() mirror;
    apply {
#ifdef WITH_INT
        if (ig_intr_md_for_dprsr.mirror_type == (bit<3>)MirrorType_t.INT_LOCAL_REPORT) {
            mirror.emit<int_mirror_metadata_t>(fabric_md.mirror.mirror_session_id,
                                               fabric_md.int_mirror);
        }
#endif // WITH_INT
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
#ifdef WITH_SPGW
    Checksum() outer_ipv4_checksum;
#endif // WITH_SPGW
#ifdef WITH_INT
    Checksum() report_ipv4_checksum;
#endif // WITH_INT

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
#ifdef WITH_SPGW
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
#endif // WITH_SPGW
#ifdef WITH_INT
        if (hdr.report_ipv4.isValid()) {
            hdr.report_ipv4.hdr_checksum = report_ipv4_checksum.update({
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
#endif // WITH_INT
        egress_mirror.apply(hdr, fabric_md, eg_intr_md_for_dprsr);

        packet.emit(hdr.fake_ethernet);
        packet.emit(hdr.packet_in);
#ifdef WITH_INT
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_eth_type);
        packet.emit(hdr.report_mpls);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_fixed_header);
        packet.emit(hdr.common_report_header);
        packet.emit(hdr.local_report_header);
#endif // WITH_INT
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan_tag);
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
        packet.emit(hdr.inner_vlan_tag);
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
        packet.emit(hdr.eth_type);
        packet.emit(hdr.mpls);
#ifdef WITH_SPGW
        packet.emit(hdr.outer_ipv4);
        packet.emit(hdr.outer_udp);
        packet.emit(hdr.outer_gtpu);
#endif // WITH_SPGW
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
#ifdef WITH_SPGW
        // in case we parsed a GTPU packet but did not decap it
        // these should never happen at the same time as the outer GTPU tunnel headers
        packet.emit(hdr.gtpu);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.inner_icmp);
#endif // WITH_SPGW
    }
}



#endif // __PARSER__
