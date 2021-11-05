// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

/*
    This file contains additional headers/structs used by bmv2.
    Extending p4src/shared/header.p4 with this file to avoid `#ifdef`s.
*/

#ifndef __HEADER_V1MODEL__
#define __HEADER_V1MODEL__

#include "shared/header.p4"

// This struct encapsulates the ingress and egress metadata for bmv2.
// The reason behind this struct is to have the same metadata structure defined for TNA.
struct fabric_v1model_metadata_t {

    // The skip_egress emulates the bypass_egress bit in intrinsic metadata for TNA.
    // Reference: https://github.com/barefootnetworks/Open-Tofino/blob/6a8432eab97bfd1d4805cf24c2c838470840f522/share/p4c/p4include/tofino.p4#L126-L127
    bool                      skip_egress;
    // Recirculate flag is needed for bmv2 to handle the SPGW UE to UE traffic.
    bool                      do_recirculate;

    fabric_ingress_metadata_t ingress;
    fabric_egress_metadata_t  egress;
}

// This struct encapsulates all the headers that are in ingress_headers but not
// in egress_headers. In this way, we're consistent in the deparser (we do not see hdr.ingress_h being deparsed)
struct egress_extended_headers_t {
    // Some fields in this struct are renamed (outer_*).
    // To better understand their meaning, look at deparser.
    // A document with all the mapping is being redacted. TODO

    // If you add a header in ingress_header_t and not in egress_header_t, then
    // you have to specify it in this struct (for bmv2)

    tcp_t outer_tcp;
    icmp_t outer_icmp;
    vxlan_t vxlan;
    // Inner ethernet and eth_types are needed in vxlan.
    ethernet_t inner_ethernet;
    eth_type_t inner_eth_type;
    tcp_t tcp;
    icmp_t icmp;
}

struct v1model_header_t {
    ingress_headers_t ingress_h;
    egress_headers_t egress_h;
    egress_extended_headers_t egress_extended_h;

    // In case of edit in some header, remember to synchronize the ingress and egress headers,
    // at the end of ingress pipeline or at the beginning of the egress pipeline.
    // TODO add this info in readme for bmv2.
}

error {
    PacketRejectedByParser
}

#endif // __HEADER_V1MODEL__
