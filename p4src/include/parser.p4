// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __PARSER__
#define __PARSER__

#include "header.p4"
#include "define.p4"
#ifdef WITH_INT
#include "control/int_mirror_parser.p4"
#endif // WITH_INT

parser FabricIngressParser (packet_in  packet,
    /* Fabric.p4 */
    out ingress_headers_t               hdr,
    out fabric_ingress_metadata_t      fabric_md,
    /* TNA */
    out ingress_intrinsic_metadata_t   ig_intr_md) {
    Checksum() ipv4_checksum;
    Checksum() inner_ipv4_checksum;

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        fabric_md.bridged.setValid();
        fabric_md.bridged.bmd_type = BridgedMdType_t.INGRESS_TO_EGRESS;
        fabric_md.bridged.base.ig_port = ig_intr_md.ingress_port;
        fabric_md.bridged.base.ig_tstamp = ig_intr_md.ingress_mac_tstamp;
        fabric_md.egress_port_set = false;
        fabric_md.bridged.base.ip_eth_type = 0;
#ifdef WITH_INT
        fabric_md.int_mirror_md.drop_reason = IntDropReason_t.DROP_REASON_UNKNOWN;
        fabric_md.bridged.int_bmd.gtpu_presence = GtpuPresence.NONE;
        fabric_md.int_mirror_md.gtpu_presence = GtpuPresence.NONE;
#endif // WITH_INT
        transition check_ethernet;
    }

    state check_ethernet {
        // We use ethernet-like headers to signal the presence of custom
        // metadata before the actual ethernet frame.
        fake_ethernet_t tmp = packet.lookahead<fake_ethernet_t>();
        transition select(tmp.ether_type) {
            ETHERTYPE_CPU_LOOPBACK_INGRESS: parse_fake_ethernet;
            ETHERTYPE_CPU_LOOPBACK_EGRESS: parse_fake_ethernet_and_accept;
            ETHERTYPE_PACKET_OUT: check_packet_out;
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

    state check_packet_out {
        packet_out_header_t tmp = packet.lookahead<packet_out_header_t>();
        transition select(tmp.do_forwarding) {
            0: parse_packet_out_and_accept;
            default: strip_packet_out;
        }
    }

    state parse_packet_out_and_accept {
        // Will transmit over requested egress port as-is. No need to parse further.
        packet.extract(hdr.packet_out);
        transition accept;
    }

    state strip_packet_out {
        // Remove packet-out header and process as a regular packet.
        packet.advance(ETH_HDR_BYTES * 8);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_QINQ: parse_vlan_tag;
            ETHERTYPE_VLAN &&& 0xEFFF: parse_vlan_tag; // 0x8100, 0x9100
            default: parse_untagged;
        }
    }

    state parse_vlan_tag {
        packet.extract(hdr.vlan_tag);
        // Initialize lookup metadata. Packets without a VLAN header will be
        // treated as belonging to a default VLAN ID
        fabric_md.bridged.base.vlan_id = hdr.vlan_tag.vlan_id;
        // fabric_md.bridged.base.vlan_cfi = hdr.vlan_tag.cfi;
        // fabric_md.bridged.base.vlan_pri = hdr.vlan_tag.pri;
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
        fabric_md.bridged.base.inner_vlan_id = hdr.inner_vlan_tag.vlan_id;
        // fabric_md.bridged.base.inner_vlan_cfi = hdr.inner_vlan_tag.cfi;
        // fabric_md.bridged.base.inner_vlan_pri = hdr.inner_vlan_tag.pri;
        transition parse_eth_type;
    }
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION

    state parse_untagged {
        // Sets default vlan
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        // fabric_md.bridged.base.vlan_cfi = 3w0;
        // fabric_md.bridged.base.vlan_pri = 1w0;
        transition parse_eth_type;
    }

    state parse_eth_type {
        packet.extract(hdr.eth_type);
        transition select(hdr.eth_type.value) {
            ETHERTYPE_MPLS: parse_mpls;
            ETHERTYPE_IPV4: parse_non_mpls;
            ETHERTYPE_IPV6: parse_non_mpls;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.mpls);
        fabric_md.bridged.base.mpls_label = hdr.mpls.label;
        fabric_md.bridged.base.mpls_ttl = hdr.mpls.ttl;
        // There is only one MPLS label for this fabric.
        // Assume header after MPLS header is IPv4/IPv6
        // Lookup first 4 bits for version
        transition select(packet.lookahead<bit<IP_VER_BITS>>()) {
            IP_VERSION_4: parse_ipv4;
            IP_VERSION_6: parse_ipv6;
            default: reject;
        }
    }

    state parse_non_mpls {
        fabric_md.bridged.base.mpls_label = 0;
        fabric_md.bridged.base.mpls_ttl = DEFAULT_MPLS_TTL + 1;
        transition select(hdr.eth_type.value) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        fabric_md.routing_ipv4_dst = hdr.ipv4.dst_addr;
        fabric_md.bridged.base.ip_eth_type = ETHERTYPE_IPV4;
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
        // FIXME: remove ipv6 support or test it
        //  https://github.com/stratum/fabric-tna/pull/227
        // fabric_md.ip_proto = hdr.ipv6.next_hdr;
        fabric_md.bridged.base.ip_eth_type = ETHERTYPE_IPV6;
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
        gtpu_t gtpu = packet.lookahead<gtpu_t>();
        transition select(hdr.udp.dport, gtpu.version, gtpu.msgtype) {
            (GTPU_UDP_PORT, GTP_V1, GTPU_GPDU): parse_gtpu;
            // Treat GTP control traffic as payload.
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag) {
            (0, 0, 0): set_gtpu_only;
            default: parse_gtpu_options;
        }
    }

    state set_gtpu_only {
#ifdef WITH_INT
        // Signal egress to strip the GTP-U tunnel headers inside INT reports.
        // Updated by SpgwIngress if we do decap.
        fabric_md.bridged.int_bmd.gtpu_presence = GtpuPresence.GTPU_ONLY;
        // Do the same for ingress-to-egress mirrors for drop reporting. Not
        // modified by decap action, as the mirrored pkt at egress will be the
        // same seen at the ingress parser.
        fabric_md.int_mirror_md.gtpu_presence = GtpuPresence.GTPU_ONLY;
#endif // WITH_INT
        transition parse_inner_ipv4;
    }

    state parse_gtpu_options {
        packet.extract(hdr.gtpu_options);
        bit<8> gtpu_ext_len = packet.lookahead<bit<8>>();
        transition select(hdr.gtpu_options.next_ext, gtpu_ext_len) {
            (GTPU_NEXT_EXT_PSC, GTPU_EXT_PSC_LEN): parse_gtpu_ext_psc;
            default: accept;
        }
    }

    state parse_gtpu_ext_psc {
        packet.extract(hdr.gtpu_ext_psc);
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.gtpu_presence = GtpuPresence.GTPU_WITH_PSC;
        fabric_md.int_mirror_md.gtpu_presence = GtpuPresence.GTPU_WITH_PSC;
#endif // WITH_INT
        transition select(hdr.gtpu_ext_psc.next_ext) {
            GTPU_NEXT_EXT_NONE: parse_inner_ipv4;
            default: accept;
        }
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

}

control FabricIngressMirror(
    in ingress_headers_t hdr,
    in fabric_ingress_metadata_t fabric_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
    Mirror() mirror;
    apply {
#ifdef WITH_INT
        if (ig_intr_md_for_dprsr.mirror_type == (bit<3>)FabricMirrorType_t.INT_REPORT) {
            mirror.emit<int_mirror_metadata_t>(fabric_md.bridged.int_bmd.mirror_session_id,
                                               fabric_md.int_mirror_md);
        }
#endif // WITH_INT
    }
}

control FabricIngressDeparser(packet_out packet,
    /* Fabric.p4 */
    inout ingress_headers_t hdr,
    in fabric_ingress_metadata_t fabric_md,
    /* TNA */
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    FabricIngressMirror() ingress_mirror;

    apply {
        ingress_mirror.apply(hdr, fabric_md, ig_intr_md_for_dprsr);
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
        // in case we parsed a GTPU packet but did not decap it
        packet.emit(hdr.gtpu);
        packet.emit(hdr.gtpu_options);
        packet.emit(hdr.gtpu_ext_psc);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.inner_icmp);
    }
}

parser FabricEgressParser (packet_in packet,
    /* Fabric.p4 */
    out egress_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(eg_intr_md);
        fabric_md.cpu_port = 0;
        common_egress_metadata_t common_eg_md = packet.lookahead<common_egress_metadata_t>();
        transition select(common_eg_md.bmd_type, common_eg_md.mirror_type) {
            (BridgedMdType_t.INGRESS_TO_EGRESS, _): parse_bridged_md;
#ifdef WITH_INT
            (BridgedMdType_t.EGRESS_MIRROR, FabricMirrorType_t.INT_REPORT): parse_int_report_mirror;
            (BridgedMdType_t.INGRESS_MIRROR, FabricMirrorType_t.INT_REPORT): parse_int_report_mirror;
#endif // WITH_INT
            default: reject;
        }
    }

    state parse_bridged_md {
        packet.extract(fabric_md.bridged);
#ifdef WITH_SPGW
        // Allocate GTP-U encap fields on the T-PHV. Set headers as valid later.
        /** outer_ipv4 **/
        hdr.outer_ipv4.version           = 4w4;
        hdr.outer_ipv4.ihl               = 4w5;
        hdr.outer_ipv4.dscp              = 0;
        hdr.outer_ipv4.ecn               = 0;
        // hdr.outer_ipv4.total_len      = update later
        hdr.outer_ipv4.identification    = 0x1513; // From NGIC, TODO: Needs to be dynamic
        hdr.outer_ipv4.flags             = 0;
        hdr.outer_ipv4.frag_offset       = 0;
        hdr.outer_ipv4.ttl               = DEFAULT_IPV4_TTL;
        hdr.outer_ipv4.protocol          = PROTO_UDP;
        // hdr.outer_ipv4.hdr_checksum   = update later
        hdr.outer_ipv4.src_addr          = fabric_md.bridged.spgw.gtpu_tunnel_sip;
        hdr.outer_ipv4.dst_addr          = fabric_md.bridged.spgw.gtpu_tunnel_dip;
        /** outer_udp **/
        hdr.outer_udp.sport              = fabric_md.bridged.spgw.gtpu_tunnel_sport;
        hdr.outer_udp.dport              = GTPU_UDP_PORT;
        // hdr.outer_udp.len             = update later
        // hdr.outer_udp.checksum        = update later
        /** outer_gtpu **/
        hdr.outer_gtpu.version           = GTP_V1;
        hdr.outer_gtpu.pt                = GTP_PROTOCOL_TYPE_GTP;
        hdr.outer_gtpu.spare             = 0;
        // hdr.outer_gtpu.ex_flag        = update later
        hdr.outer_gtpu.seq_flag          = 0;
        hdr.outer_gtpu.npdu_flag         = 0;
        hdr.outer_gtpu.msgtype           = GTPU_GPDU;
        // hdr.outer_gtpu.msglen         = update later
        hdr.outer_gtpu.teid              = fabric_md.bridged.spgw.gtpu_teid;
        /** outer_gtpu_options **/
        hdr.outer_gtpu_options.seq_num   = 0;
        hdr.outer_gtpu_options.n_pdu_num = 0;
        hdr.outer_gtpu_options.next_ext  = GTPU_NEXT_EXT_PSC;
        /** outer_gtpu_ext_psc **/
        hdr.outer_gtpu_ext_psc.len       = GTPU_EXT_PSC_LEN;
        hdr.outer_gtpu_ext_psc.type      = GTPU_EXT_PSC_TYPE_DL;
        hdr.outer_gtpu_ext_psc.spare0    = 0;
        hdr.outer_gtpu_ext_psc.ppp       = 0;
        hdr.outer_gtpu_ext_psc.rqi       = 0;
        // hdr.outer_gtpu_ext_psc.qfi    = update later
        hdr.outer_gtpu_ext_psc.next_ext  = GTPU_NEXT_EXT_NONE;
#endif // WITH_SPGW
#ifdef WITH_INT
        fabric_md.int_mirror_md.gtpu_presence = fabric_md.bridged.int_bmd.gtpu_presence;
#endif // WITH_INT
        transition check_ethernet;
    }

#ifdef WITH_INT
    state parse_int_report_mirror {
        IntReportMirrorParser.apply(packet, hdr, fabric_md, eg_intr_md);
        transition accept;
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
#ifdef WITH_DOUBLE_VLAN_TERMINATION
            ETHERTYPE_QINQ: parse_vlan_tag;
#endif // WITH_DOUBLE_VLAN_TERMINATION
            ETHERTYPE_VLAN &&& 0xEFFF: parse_vlan_tag;
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
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_MPLS: parse_mpls;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.mpls);
        transition select(packet.lookahead<bit<IP_VER_BITS>>()) {
            IP_VERSION_4: parse_ipv4;
            IP_VERSION_6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition accept;
    }
}

control FabricEgressMirror(
    in egress_headers_t hdr,
    in fabric_egress_metadata_t fabric_md,
    in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    Mirror() mirror;
    apply {
#ifdef WITH_INT
        if (eg_intr_md_for_dprsr.mirror_type == (bit<3>)FabricMirrorType_t.INT_REPORT) {
            mirror.emit<int_mirror_metadata_t>(fabric_md.bridged.int_bmd.mirror_session_id,
                                               fabric_md.int_mirror_md);
        }
#endif // WITH_INT
    }
}

control FabricEgressDeparser(packet_out packet,
    /* Fabric.p4 */
    inout egress_headers_t hdr,
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
        packet.emit(hdr.drop_report_header);
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
        packet.emit(hdr.outer_gtpu_options);
        packet.emit(hdr.outer_gtpu_ext_psc);
#endif // WITH_SPGW
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
    }
}

#endif // __PARSER__
