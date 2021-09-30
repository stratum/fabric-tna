// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_PARSER__
#define __INT_PARSER__

// Parser of mirrored or bridged packets that will become INT reports.
// To simplify handling of reports at the collector, we remove all headers between
// Ethernet and IPv4 (the inner one if processing a GTP-U encapped packet).
// We support generating reports only for IPv4 packets, i.e., cannot report IPv6 traffic.
parser IntReportParser (packet_in packet,
    inout egress_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        fabric_md.is_int_recirc = true;
        common_egress_metadata_t common_eg_md = packet.lookahead<common_egress_metadata_t>();
        transition select(eg_intr_md.deflection_flag, common_eg_md.bmd_type, common_eg_md.mirror_type) {
            (1, _, _): parse_int_deflected_drop;
            (0, BridgedMdType_t.INT_INGRESS_DROP, _): parse_int_ingress_drop;
            (0, BridgedMdType_t.EGRESS_MIRROR, FabricMirrorType_t.INT_REPORT): parse_int_report_mirror;
            default: reject;
        }
    }

    state parse_int_report_mirror {
        packet.extract(fabric_md.int_report_md);
        fabric_md.bridged.bmd_type = fabric_md.int_report_md.bmd_type;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.bridged.base.mpls_label = 0; // do not push an MPLS label
#ifdef WITH_SPGW
        fabric_md.bridged.spgw.skip_spgw = true;
#endif // WITH_SPGW

        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.int_report_md.ig_tstamp;

        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.int_report_md.ig_port;
        hdr.common_report_header.eg_port = fabric_md.int_report_md.eg_port;
        hdr.common_report_header.queue_id = fabric_md.int_report_md.queue_id;

        /** local/drop_report_header (set valid later) **/
        hdr.local_report_header.queue_occupancy = fabric_md.int_report_md.queue_occupancy;
        hdr.local_report_header.eg_tstamp = fabric_md.int_report_md.eg_tstamp;
        hdr.drop_report_header.drop_reason = fabric_md.int_report_md.drop_reason;

        transition set_common_int_headers;
    }

    state parse_int_ingress_drop {
        packet.extract(fabric_md.bridged);
        fabric_md.int_report_md.bmd_type = BridgedMdType_t.INT_INGRESS_DROP;
        fabric_md.int_report_md.encap_presence = fabric_md.bridged.base.encap_presence;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;

        /** drop_report_header **/
        hdr.drop_report_header.drop_reason = fabric_md.bridged.int_bmd.drop_reason;
        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.bridged.base.ig_port;
        hdr.common_report_header.eg_port = 0;
        hdr.common_report_header.queue_id = 0;
        transition set_common_int_drop_headers;
    }

    // This state parse packets which deflected by the traffic manager.
    // See ptf/run/tm/chassis_config.pb.txt for deflect-on-drop port config.
    state parse_int_deflected_drop {
        packet.extract(fabric_md.bridged);
        fabric_md.int_report_md.bmd_type = BridgedMdType_t.DEFLECTED;
        fabric_md.int_report_md.encap_presence = fabric_md.bridged.base.encap_presence;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;

        /** drop_report_header **/
        hdr.drop_report_header.drop_reason = IntDropReason_t.DROP_REASON_TRAFFIC_MANAGER;
        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.bridged.base.ig_port;
        hdr.common_report_header.eg_port = fabric_md.bridged.int_bmd.egress_port;
        hdr.common_report_header.queue_id = fabric_md.bridged.int_bmd.queue_id;
        transition set_common_int_drop_headers;
    }

    state set_common_int_drop_headers {
        fabric_md.int_report_md.setValid();
        fabric_md.int_report_md.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.int_report_md.report_type = INT_REPORT_TYPE_DROP;
        fabric_md.int_report_md.mirror_type = FabricMirrorType_t.INVALID;

        /** drop_report_header **/
        hdr.drop_report_header.setValid();
        transition set_common_int_headers;
    }

    state set_common_int_headers {
        // Initialize report headers here to allocate constant fields on the
        // T-PHV (and save on PHV resources).
        /** report_ethernet **/
        hdr.report_ethernet.setValid();
        // hdr.report_ethernet.dst_addr = update later
        // hdr.report_ethernet.src_addr = update later

        /** report_eth_type **/
        hdr.report_eth_type.setValid();
        // hdr.report_eth_type.value = update later

        /** report_mpls (set valid later) **/
        // hdr.report_mpls.label = update later
        hdr.report_mpls.tc = 0;
        hdr.report_mpls.bos = 0;
        hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;

        /** report_ipv4 **/
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4w4;
        hdr.report_ipv4.ihl = 4w5;
        // TODO BEFORE MERGE: confirm with DI team whether this can be zero
        hdr.report_ipv4.dscp = 0;
        hdr.report_ipv4.ecn = 2w0;
        // hdr.report_ipv4.total_len = update later
        // hdr.report_ipv4.identification = update later
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.report_ipv4.protocol = PROTO_UDP;
        // hdr.report_ipv4.hdr_checksum = update later
        // hdr.report_ipv4.src_addr = update later
        // hdr.report_ipv4.dst_addr = update later

        /** report_udp **/
        hdr.report_udp.setValid();
        hdr.report_udp.sport = 0;
        // hdr.report_udp.dport = update later
        // hdr.report_udp.len = update later
        // hdr.report_udp.checksum = update never!

        /** report_fixed_header **/
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 0;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        // hdr.report_fixed_header.d = update later
        // hdr.report_fixed_header.q = update later
        // hdr.report_fixed_header.f = update later
        hdr.report_fixed_header.rsvd = 0;
        // hdr.report_fixed_header.hw_id = update later
        // hdr.report_fixed_header.seq_no = update later

        /** common_report_header **/
        hdr.common_report_header.setValid();
        // hdr.common_report_header.switch_id = update later

        transition check_ethernet;
    }

    state check_ethernet {
        fake_ethernet_t tmp = packet.lookahead<fake_ethernet_t>();
        transition select(tmp.ether_type) {
            ETHERTYPE_CPU_LOOPBACK_INGRESS: set_cpu_loopback_ingress;
            ETHERTYPE_CPU_LOOPBACK_EGRESS: set_cpu_loopback_ingress;
            default: parse_eth_hdr;
        }
    }

    state set_cpu_loopback_ingress {
        hdr.fake_ethernet.setValid();
        // We will generate the INT report, which will be re-circulated back to the Ingress pipe.
        // We need to set it back to ETHERTYPE_CPU_LOOPBACK_INGRESS to enable processing
        // the INT report in the Ingress pipe as a standard INT report, instead of punting it to CPU.
        hdr.fake_ethernet.ether_type = ETHERTYPE_CPU_LOOPBACK_INGRESS;
        packet.advance(ETH_HDR_BYTES * 8);
        transition parse_eth_hdr;
    }

    state parse_eth_hdr {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
#ifdef WITH_DOUBLE_VLAN_TERMINATION
            ETHERTYPE_QINQ: strip_vlan;
#endif // WITH_DOUBLE_VLAN_TERMINATION
            ETHERTYPE_VLAN &&& 0xEFFF: strip_vlan;
            default: check_eth_type;
        }
    }

    state strip_vlan {
        packet.advance(VLAN_HDR_BYTES * 8);
        transition select(packet.lookahead<bit<16>>()) {
// TODO: support stripping double VLAN tag
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
            ETHERTYPE_VLAN: reject;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
            default: check_eth_type;
        }
    }

    state check_eth_type {
        packet.extract(hdr.eth_type);
        transition select(hdr.eth_type.value, fabric_md.int_report_md.encap_presence) {
            (ETHERTYPE_MPLS, _): strip_mpls;
            (ETHERTYPE_IPV4, EncapPresence.NONE): handle_ipv4;
            (ETHERTYPE_IPV4, EncapPresence.GTPU_ONLY): strip_ipv4_udp_gtpu;
            (ETHERTYPE_IPV4, EncapPresence.GTPU_WITH_PSC): strip_ipv4_udp_gtpu_psc;
            (ETHERTYPE_IPV4, EncapPresence.VXLAN): strip_ipv4_udp_vxlan;
            default: reject;
        }
    }

    // We expect MPLS to be present only for mirrored packets (ingress-to-egress
    // or egress-to-egress). We will fix the ethertype in the INT control block.
    state strip_mpls {
        packet.advance(MPLS_HDR_BYTES * 8);
        bit<IP_VER_BITS> ip_ver = packet.lookahead<bit<IP_VER_BITS>>();
        transition select(ip_ver, fabric_md.int_report_md.encap_presence) {
            (IP_VERSION_4, EncapPresence.NONE): handle_ipv4;
            (IP_VERSION_4, EncapPresence.GTPU_ONLY): strip_ipv4_udp_gtpu;
            (IP_VERSION_4, EncapPresence.GTPU_WITH_PSC): strip_ipv4_udp_gtpu_psc;
            (IP_VERSION_4, EncapPresence.VXLAN): strip_ipv4_udp_vxlan;
            default: reject;
        }
    }

    state strip_ipv4_udp_gtpu {
        packet.advance((IPV4_HDR_BYTES + UDP_HDR_BYTES + GTPU_HDR_BYTES) * 8);
        transition handle_ipv4;
    }

    state strip_ipv4_udp_gtpu_psc {
        packet.advance((IPV4_HDR_BYTES + UDP_HDR_BYTES + GTPU_HDR_BYTES
                + GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES) * 8);
        transition handle_ipv4;
    }

    state strip_ipv4_udp_vxlan {
        packet.advance((IPV4_HDR_BYTES + UDP_HDR_BYTES + VXLAN_HDR_BYTES) * 8);
        // Skip the Ethernet header.
        // It will be removed from a packet and the outer Ethernet will be used
        // as the inner Ethernet header.
        packet.advance((ETH_HDR_BYTES) * 8);
        transition handle_ipv4;
    }

    state handle_ipv4 {
        // Extract only the length, required later to compute the lenght of the
        // report encap headers.
        ipv4_t ipv4 = packet.lookahead<ipv4_t>();
        fabric_md.int_ipv4_len = ipv4.total_len;
        transition accept;
    }
}

#endif // __INT_MIRROR_PARSER__
