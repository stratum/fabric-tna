// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_MIRROR_PARSER__
#define __INT_MIRROR_PARSER__

// Parser of mirrored packets that will become INT reports. To simplify handling
// of reports at the collector, we remove all headers between Ethernet and IPv4
// (the inner one if processing a GTP-U encapped packet). We support generating
// reports only for IPv4 packets, i.e., cannot report IPv6 traffic.
parser IntReportMirrorParser (packet_in packet,
    /* Fabric.p4 */
    out egress_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(fabric_md.int_mirror_md);
        fabric_md.bridged.bmd_type = fabric_md.int_mirror_md.bmd_type;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.bridged.base.mpls_label = 0; // do not push an MPLS label
#ifdef WITH_SPGW
        fabric_md.bridged.spgw.skip_spgw = true; // skip spgw encap
#endif // WITH_SPGW
        // Initialize report headers here to allocate constant fields on T-PHV
        // (and save on PHV resources). Note that initializing the full header
        // with hdr = {...} sets the validity bit to 1. We will disable unwanted
        // headers in the INT control block.
        hdr.report_mpls = {
            0, // label, update later
            0, // tc
            1, // bos
            DEFAULT_MPLS_TTL // ttl
        };
        hdr.report_ipv4 = {
            4w4, // version
            4w5, // ihl
            INT_DSCP,
            2w0, // ecn
            0, // total_length, update later
            0, // identification, update later
            0, // flags,
            0, // frag_offset
            DEFAULT_IPV4_TTL,
            PROTO_UDP,
            0, // checksum, update later
            0, // Src IP, update later
            0  // Dst IP, update later
        };
        hdr.report_udp = {
            0, // sport
            0, // dport, update later
            0, // len, update later
            0 // checksum, update never
        };
        hdr.report_fixed_header = {
            0, // version
            NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER,
            0, // d
            0, // q
            0, // f
            0, // rsvd
            0, // hw_id, update later
            0, // seq_no, update later
            fabric_md.int_mirror_md.ig_tstamp
        };
        hdr.common_report_header = {
            0, // switch_id, update later
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
#ifdef WITH_SPGW
        transition select(hdr.eth_type.value, fabric_md.int_mirror_md.strip_gtpu) {
            (ETHERTYPE_MPLS, _): strip_mpls;
            (ETHERTYPE_IPV4, 0): handle_ipv4;
            (ETHERTYPE_IPV4, 1): strip_ipv4_udp_gtpu;
            // FIXME: remove ipv6 support or test it
            //  https://github.com/stratum/fabric-tna/pull/227
            // (ETHERTYPE_IPV6, 0): parse_ipv6;
            // (ETHERTYPE_IPV6, 1): strip_ipv6_udp_gtpu;
            default: reject;
        }
#else
        transition select(hdr.eth_type.value) {
            ETHERTYPE_MPLS: strip_mpls;
            ETHERTYPE_IPV4: handle_ipv4;
            // ETHERTYPE_IPV6: parse_ipv6;
            default: reject;
        }
#endif // WITH_SPGW
    }

    // We expect MPLS to be present only for egress-to-egress clones for INT
    // reporting, in which case we need to remove the MPLS header as not
    // supported by the collector. After stripping the MPLS header, we still
    // need to fix the ethertype. We will do this at the beginning of the INT
    // control block.
    state strip_mpls {
        packet.advance(MPLS_HDR_BYTES * 8);
        bit<IP_VER_BITS> ip_ver = packet.lookahead<bit<IP_VER_BITS>>();
#ifdef WITH_SPGW
        transition select(fabric_md.int_mirror_md.strip_gtpu, ip_ver) {
            (1, IP_VERSION_4): strip_ipv4_udp_gtpu;
            // (1, IP_VERSION_6): strip_ipv6_udp_gtpu;
            (0, IP_VERSION_4): handle_ipv4;
            // (0, IP_VERSION_6): parse_ipv6;
            default: reject;
        }
#else
        transition select(ip_ver) {
            IP_VERSION_4: handle_ipv4;
            // IP_VERSION_6: parse_ipv6;
            default: reject;
        }
#endif // WITH_SPGW
    }

#ifdef WITH_SPGW
    state strip_ipv4_udp_gtpu {
        packet.advance((IPV4_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES) * 8);
        transition handle_ipv4;
    }

    // state strip_ipv6_udp_gtpu {
    //     packet.advance((IPV6_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES) * 8);
    //     transition parse_ipv6;
    // }
#endif // WITH_SPGW

    state handle_ipv4 {
        // Extract only the length field, require later to compute the lenght
        // for the report encap headers.
        ipv4_t ipv4 = packet.lookahead<ipv4_t>();
        fabric_md.int_ipv4_len = ipv4.total_len;
        transition accept;
    }
}

#endif // __INT_MIRROR_PARSER__
