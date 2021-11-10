// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __PARSER__
#define __PARSER__

#include "v1model/include/header_v1model.p4"
#include "v1model/include/define_v1model.p4"

parser FabricParser (packet_in packet,
                     out v1model_header_t hdr,
                     inout fabric_v1model_metadata_t fabric_md,
                     inout standard_metadata_t standard_md) {

    state start {
        fabric_md.ingress.bridged.setValid();
        fabric_md.ingress.bridged.bmd_type = BridgedMdType_t.INGRESS_TO_EGRESS;
        fabric_md.ingress.bridged.base.ig_port = standard_md.ingress_port;
        fabric_md.ingress.bridged.base.ig_tstamp = standard_md.ingress_global_timestamp;
        fabric_md.ingress.egress_port_set = false;
        fabric_md.ingress.punt_to_cpu = false;
        fabric_md.ingress.bridged.base.ip_eth_type = 0;
        fabric_md.ingress.bridged.base.encap_presence = EncapPresence.NONE;

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

    state check_packet_out {
            packet_out_header_t tmp = packet.lookahead<packet_out_header_t>();
            transition select(tmp.do_forwarding) {
                0: parse_packet_out_and_accept;
                default: strip_packet_out;
            }
    }

    state parse_packet_out_and_accept {
        // Will transmit over requested egress port as-is. No need to parse further.
        packet.extract(hdr.ingress_h.packet_out);
        transition accept;
    }

    state strip_packet_out {
        // Remove packet-out header and process as a regular packet.
        packet.advance(ETH_HDR_BYTES * 8);
        transition parse_ethernet;
    }

    state parse_fake_ethernet {
        packet.extract(hdr.ingress_h.fake_ethernet);
        fake_ethernet_t tmp = packet.lookahead<fake_ethernet_t>();
        transition select(tmp.ether_type) {
            default: parse_ethernet;
        }
    }

    state parse_fake_ethernet_and_accept {
        packet.extract(hdr.ingress_h.fake_ethernet);
        // Will punt to CPU as-is. No need to parse further.
        transition accept;
    }

    state parse_ethernet {
        packet.extract(hdr.ingress_h.ethernet);
        transition select(packet.lookahead<bit<16>>()) {
            ETHERTYPE_QINQ: parse_vlan_tag;
            ETHERTYPE_VLAN &&& 0xEFFF: parse_vlan_tag; // 0x8100, 0x9100
            default: parse_untagged;
        }
    }

    state parse_vlan_tag {
        packet.extract(hdr.ingress_h.vlan_tag);
        // Initialize lookup metadata. Packets without a VLAN header will be
        // treated as belonging to a default VLAN ID
        fabric_md.ingress.bridged.base.vlan_id = hdr.ingress_h.vlan_tag.vlan_id;
        // fabric_md.ingress.bridged.base.vlan_cfi = hdr.ingress_h.vlan_tag.cfi;
        // fabric_md.ingress.bridged.base.vlan_pri = hdr.ingress_h.vlan_tag.pri;
        transition select(packet.lookahead<bit<16>>()) {
            default: parse_eth_type;
        }
    }

    state parse_untagged {
        // Sets default vlan
        fabric_md.ingress.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        // fabric_md.ingress.bridged.base.vlan_cfi = 3w0;
        // fabric_md.ingress.bridged.base.vlan_pri = 1w0;
        transition parse_eth_type;
    }

    state parse_eth_type {
        packet.extract(hdr.ingress_h.eth_type);
        transition select(hdr.ingress_h.eth_type.value) {
            ETHERTYPE_MPLS: parse_mpls;
            ETHERTYPE_IPV4: parse_non_mpls;
            ETHERTYPE_IPV6: parse_non_mpls;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.ingress_h.mpls);
        fabric_md.ingress.bridged.base.mpls_label = hdr.ingress_h.mpls.label;
        fabric_md.ingress.bridged.base.mpls_ttl = hdr.ingress_h.mpls.ttl;
        // There is only one MPLS label for this fabric.
        // Assume header after MPLS header is IPv4/IPv6
        // Lookup first 4 bits for version
        transition select(packet.lookahead<bit<IP_VER_BITS>>()) {
            IP_VERSION_4: parse_ipv4;
            IP_VERSION_6: parse_ipv6;
            default: reject_packet;
        }
    }

    state reject_packet{
        // 'default: reject;' Not supported by bmv2.
        // Use verify(false, error.PacketRejectedByParser) to set the parser error and use it to drop in Ingress.
        // for more information https://github.com/p4lang/behavioral-model/blob/971732f48570f848a27a8f54b25b7447732d8591/docs/simple_switch.md
        verify(false, error.PacketRejectedByParser);
        transition accept;
    }

    state parse_non_mpls {
        fabric_md.ingress.bridged.base.mpls_label = 0;
        fabric_md.ingress.bridged.base.mpls_ttl = DEFAULT_MPLS_TTL + 1;
        transition select(hdr.ingress_h.eth_type.value) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ingress_h.ipv4);
        fabric_md.ingress.routing_ipv4_dst = hdr.ingress_h.ipv4.dst_addr;
        fabric_md.ingress.bridged.base.ip_eth_type = ETHERTYPE_IPV4;
        //ipv4_checksum.add(hdr.ingress_h.ipv4);
        //fabric_md.ingress.ipv4_checksum_err = ipv4_checksum.verify();
        // Need header verification?
        transition select(hdr.ingress_h.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ingress_h.ipv6);
        // FIXME: remove ipv6 support or test it
        //  https://github.com/stratum/fabric-tna/pull/227
        // fabric_md.ingress.ip_proto = hdr.ingress_h.ipv6.next_hdr;
        fabric_md.ingress.bridged.base.ip_eth_type = ETHERTYPE_IPV6;
        transition select(hdr.ingress_h.ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.ingress_h.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.ingress_h.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.ingress_h.udp);
        gtpu_t gtpu = packet.lookahead<gtpu_t>();
        transition select(hdr.ingress_h.udp.dport, gtpu.version, gtpu.msgtype) {
            (GTPU_UDP_PORT, GTP_V1, GTPU_GPDU): parse_gtpu;
            (VXLAN_UDP_PORT, _, _): parse_vxlan;
            // Treat GTP control traffic as payload.
            default: accept;
        }
    }

    state parse_gtpu {
        packet.extract(hdr.ingress_h.gtpu);
        transition select(hdr.ingress_h.gtpu.ex_flag, hdr.ingress_h.gtpu.seq_flag, hdr.ingress_h.gtpu.npdu_flag) {
            (0, 0, 0): set_gtpu_only;
            default: parse_gtpu_options;
        }
    }

    state set_gtpu_only {
        fabric_md.ingress.bridged.base.encap_presence = EncapPresence.GTPU_ONLY;
        transition parse_inner_ipv4;
    }

    state parse_gtpu_options {
        packet.extract(hdr.ingress_h.gtpu_options);
        bit<8> gtpu_ext_len = packet.lookahead<bit<8>>();
        transition select(hdr.ingress_h.gtpu_options.next_ext, gtpu_ext_len) {
            (GTPU_NEXT_EXT_PSC, GTPU_EXT_PSC_LEN): parse_gtpu_ext_psc;
            default: accept;
        }
    }

    state parse_gtpu_ext_psc {
        packet.extract(hdr.ingress_h.gtpu_ext_psc);
        fabric_md.ingress.bridged.base.encap_presence = EncapPresence.GTPU_WITH_PSC;
        transition select(hdr.ingress_h.gtpu_ext_psc.next_ext) {
            GTPU_NEXT_EXT_NONE: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_vxlan {
        packet.extract(hdr.ingress_h.vxlan);
        fabric_md.ingress.bridged.base.encap_presence = EncapPresence.VXLAN;
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract(hdr.ingress_h.inner_ethernet);
        packet.extract(hdr.ingress_h.inner_eth_type);
        transition select(hdr.ingress_h.inner_eth_type.value) {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.ingress_h.inner_ipv4);
        //inner_ipv4_checksum.add(hdr.ingress_h.inner_ipv4);
        //fabric_md.ingress.inner_ipv4_checksum_err = inner_ipv4_checksum.verify();
        transition select(hdr.ingress_h.inner_ipv4.protocol) {
            PROTO_TCP: parse_inner_tcp;
            PROTO_UDP: parse_inner_udp;
            PROTO_ICMP: parse_inner_icmp;
            default: accept;
        }
    }

    state parse_inner_tcp {
        packet.extract(hdr.ingress_h.inner_tcp);
        transition accept;
    }

    state parse_inner_udp {
        packet.extract(hdr.ingress_h.inner_udp);
        transition accept;
    }

    state parse_inner_icmp {
        packet.extract(hdr.ingress_h.inner_icmp);
        transition accept;
    }

}

control FabricDeparser(packet_out       packet,
                       in v1model_header_t hdr) {

    // bmv2 deparser should emit headers contained in egress_header or egress_extended_header_t, not ingress_headers_t.
    //  This behavior is intended to keep things as consistent as possible w.r.t. TNA implementation.
    apply {

            packet.emit(hdr.ingress_h.fake_ethernet);
            packet.emit(hdr.ingress_h.packet_in);
            packet.emit(hdr.ingress_h.ethernet);
            packet.emit(hdr.ingress_h.vlan_tag);
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
            packet.emit(hdr.ingress_h.inner_vlan_tag);
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
            packet.emit(hdr.ingress_h.eth_type);
            packet.emit(hdr.ingress_h.mpls);
            packet.emit(hdr.ingress_h.ipv4);
            packet.emit(hdr.ingress_h.ipv6);
            packet.emit(hdr.ingress_h.tcp);
            packet.emit(hdr.ingress_h.udp);
            packet.emit(hdr.ingress_h.icmp);
            // in case we parsed a GTPU packet but did not decap it
            packet.emit(hdr.ingress_h.gtpu);
            packet.emit(hdr.ingress_h.gtpu_options);
            packet.emit(hdr.ingress_h.gtpu_ext_psc);
            packet.emit(hdr.ingress_h.vxlan);
            packet.emit(hdr.ingress_h.inner_ethernet);
            packet.emit(hdr.ingress_h.inner_eth_type);
            packet.emit(hdr.ingress_h.inner_ipv4);
            packet.emit(hdr.ingress_h.inner_tcp);
            packet.emit(hdr.ingress_h.inner_udp);
            packet.emit(hdr.ingress_h.inner_icmp);
    }
}

#endif // __PARSER__
