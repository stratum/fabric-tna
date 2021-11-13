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

    fabric_ingress_metadata_t ingress;
    fabric_egress_metadata_t  egress;
}

struct v1model_header_t {
    ingress_headers_t ingress;
    egress_headers_t egress;

    // In case of edit in some header, remember to synchronize the ingress and egress headers,
    // at the end of ingress pipeline or at the beginning of the egress pipeline.
    // TODO add this info in readme for bmv2.
}

error {
    PacketRejectedByParser
}

#endif // __HEADER_V1MODEL__
