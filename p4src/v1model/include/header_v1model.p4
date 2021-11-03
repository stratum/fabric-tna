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
    bool                      recirculate;
    // Needed to handle the case gtpu traffic being decapped in ingress controls.
    bool                      is_gtpu_decapped;

    fabric_ingress_metadata_t ingress;
    fabric_egress_metadata_t  egress;
}

// This struct encapsulates all the headers that are in ingress_headers but not in egress_headers.
struct egress_extended_headers_t {
    // Add the ingress headers that are missing in the egress_headers to be consistent in deparser.
    tcp_t outer_tcp;
    icmp_t outer_icmp;
    gtpu_t outer_gtpu;
    gtpu_options_t outer_gtpu_options;
    gtpu_ext_psc_t outer_gtpu_ext_psc;
    vxlan_t outer_vxlan;
    // What before was inner_*, it is now no more. For better understanding when deparsing, in bmv2.
    ethernet_t ethernet;
    eth_type_t eth_type;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
}

struct v1model_header_t {
    ingress_headers_t ingress_h;
    egress_headers_t egress_h;
    egress_extended_headers_t egress_extended_h;

    // Remember to synchronize the headers between ingress and egress.


    // TODO add this info in readme for bmv2. If you add a header in ingress header and not in egress header, then
    // you have to specify it in this struct (for bmv2)
}

error {
    PacketRejectedByParser
}

#endif // __HEADER_V1MODEL__
