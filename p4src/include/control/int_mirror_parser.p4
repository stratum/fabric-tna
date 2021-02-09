// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_MIRROR_PARSER__
#define __INT_MIRROR_PARSER__

parser IntReportMirrorParser (packet_in packet,
    /* Fabric.p4 */
    out parsed_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(fabric_md.int_mirror_md);
        fabric_md.bridged.bmd_type = fabric_md.int_mirror_md.bmd_type;
        fabric_md.bridged.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.bridged.mpls_label = 0; // do not set the MPLS label later in the egress next control block.
#ifdef WITH_SPGW
        fabric_md.bridged.spgw.skip_spgw = true; // skip spgw so we won't encap it later.
#endif // WITH_SPGW

        hdr.report_fixed_header.ig_tstamp = fabric_md.int_mirror_md.ig_tstamp;
        hdr.common_report_header = {
            fabric_md.int_mirror_md.switch_id,
            fabric_md.int_mirror_md.ig_port,
            fabric_md.int_mirror_md.eg_port,
            fabric_md.int_mirror_md.queue_id
        };
        hdr.local_report_header = {
            fabric_md.int_mirror_md.queue_occupancy,
            fabric_md.int_mirror_md.eg_tstamp
        };
        hdr.drop_report_header = {
            fabric_md.int_mirror_md.drop_reason,
            0 // pad
        };
        transition parse_eth_hdr;
    }

    state parse_eth_hdr {
        packet.extract(hdr.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
#ifdef WITH_DOUBLE_VLAN_TERMINATION
            ETHERTYPE_QINQ: parse_vlan_tag;
#endif // WITH_DOUBLE_VLAN_TERMINATION
            ETHERTYPE_VLAN &&& 0xEFFF: parse_vlan_tag;
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

    state check_eth_type {
        packet.extract(hdr.eth_type);
#ifdef WITH_SPGW
        transition select(hdr.eth_type.value, fabric_md.int_mirror_md.strip_gtpu) {
            (ETHERTYPE_MPLS, _): strip_mpls;
            (ETHERTYPE_IPV4, 0): accept;
            (ETHERTYPE_IPV4, 1): strip_ipv4_udp_gtpu;
            (ETHERTYPE_IPV6, 0): accept;
            (ETHERTYPE_IPV6, 1): strip_ipv6_udp_gtpu;
            default: reject;
        }
#else
        transition select(hdr.eth_type.value) {
            ETHERTYPE_MPLS: strip_mpls;
            ETHERTYPE_IPV4: accept;
            ETHERTYPE_IPV6: accept;
            default: reject;
        }
#endif // WITH_SPGW
    }

    // We expect MPLS to be present only for egress-to-egress clones for INT
    // reporting, in which case we need to remove the MPLS header as not
    // supported by the collector. For all other cases, the MPLS label is
    // always popped in ingress and pushed again in egress (if present in
    // bridged metadata).
    // After stripping the MPLS header, we still need to fix the ethertype.
    // We will do this in the beginning of the INT control block.
    state strip_mpls {
        fabric_md.mpls_stripped = 1;
        packet.advance(MPLS_HDR_BYTES * 8);
#ifdef WITH_SPGW
        transition select(fabric_md.int_mirror_md.strip_gtpu, packet.lookahead<bit<IP_VER_BITS>>()) {
            (1, IP_VERSION_4): strip_ipv4_udp_gtpu;
            (1, IP_VERSION_6): strip_ipv6_udp_gtpu;
            (0, _): accept;
            default: reject;
        }
#else
        transition accept;
#endif // WITH_SPGW
    }

#ifdef WITH_SPGW
    state strip_ipv4_udp_gtpu {
        packet.advance((IPV4_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES) * 8);
        transition accept;
    }

    state strip_ipv6_udp_gtpu {
        packet.advance((IPV6_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES) * 8);
        transition accept;
    }
#endif // WITH_SPGW
}

#endif // __INT_MIRROR_PARSER__
