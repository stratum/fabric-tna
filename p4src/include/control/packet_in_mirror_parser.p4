// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __PACKET_IN_MIRROR_PARSER__
#define __PACKET_IN_MIRROR_PARSER__

// The parser to parser mirror packets for packet-in.
parser PacketInMirrorParser(packet_in packet,
    /* Fabric-TNA */
    out egress_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet_in_mirror_metadata_t pkt_in_md;
        packet.extract(pkt_in_md);
        // FIXME: In theory we should be able to initialize the packet-in header in
        //        this parser state, however there is a field alignment error if we
        //        initialize the field here. Now we will initialize the value in the
        //        packet_io control block.
        fabric_md.bridged.base.ig_port = pkt_in_md.ingress_port;
        hdr.packet_in.setValid();
        transition check_ethernet;
    }

    state check_ethernet {
        fake_ethernet_t tmp = packet.lookahead<fake_ethernet_t>();
        transition select(tmp.ether_type) {
            // TODO: Consider using ETHERTYPE_CPU_LOOPBACK_INGRESS &&& 0xfffe to reduce
            //       memory usage.
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
