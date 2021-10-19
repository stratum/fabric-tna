// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

/*
    This file contains additional headers used by bmv2.
*/

// This struct encapsulates the ingress and egress metadata for bmv2.
// The reason behind this struct is to have the same metadata structure defined for TNA.
struct fabric_v1model_metadata_t {

    // The skip_egress emulates the bypass_egress bit in intrinsic metadata for TNA.
    // Reference: https://github.com/barefootnetworks/Open-Tofino/blob/6a8432eab97bfd1d4805cf24c2c838470840f522/share/p4c/p4include/tofino.p4#L126-L127
    bool                      skip_egress;

    fabric_ingress_metadata_t ingress;
    fabric_egress_metadata_t  egress;
}


error {
    PacketRejectedByParser
}
