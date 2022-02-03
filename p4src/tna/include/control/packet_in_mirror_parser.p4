// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __PACKET_IN_MIRROR_PARSER__
#define __PACKET_IN_MIRROR_PARSER__

// Parses mirrored packets from the ingress pipe to generate controller packet-ins.
parser PacketInMirrorParser(packet_in packet,
    /* Fabric-TNA */
    out egress_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet_in_mirror_metadata_t pkt_in_md;
        packet.extract(pkt_in_md);
        fabric_md.bridged.base.ig_port = pkt_in_md.ingress_port;
        fake_ethernet_t tmp = packet.lookahead<fake_ethernet_t>();
        transition select(tmp.ether_type) {
            ETHERTYPE_CPU_LOOPBACK_INGRESS: strip_fake_ethernet;
            ETHERTYPE_CPU_LOOPBACK_EGRESS: strip_fake_ethernet;
            default: accept;
        }
    }

    state strip_fake_ethernet {
        packet.advance(ETH_HDR_BYTES * 8);
        transition accept;
    }
}

#endif // __PACKET_IN_MIRROR_PARSER__
