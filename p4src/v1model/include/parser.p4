// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __PARSER__
#define __PARSER__

#include "header.p4"
#include "define.p4"

parser FabricParser (packet_in packet,
                    out ingress_headers_t hdr,
                    inout fabric_ingress_metadata_t fabric_metadata,
                    inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            default: parse_ethernet;
        }
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
        }
}

control FabricDeparser(packet_out packet,
                       in         ingress_headers_t hdr) {

    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
    }
}

#endif // __PARSER__
