// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

/*
    This file contains additional headers/structs used by bmv2.
    Extending p4src/shared/header.p4 with this file to avoid `#ifdef`s.
*/

#ifndef __HEADER_V1MODEL__
#define __HEADER_V1MODEL__

#include "shared/header.p4"

struct v1model_standard_md_t {
    // This struct is needed to preserve standard_metadata when recirculating/cloning the packet,
    // Using the latest feature from p4c.

    PortId_t    ingress_port;
    PortId_t    egress_spec;
    PortId_t    egress_port;

    bit<48> ingress_global_timestamp;
    bit<48> egress_global_timestamp;
    bit<16> mcast_grp;
    bit<16> egress_rid;
    bit<1>  checksum_error;
}

// This struct encapsulates the ingress and egress metadata for bmv2.
// The reason behind this struct is to have the same metadata structure defined for TNA.
struct fabric_v1model_metadata_t {

    // The skip_egress emulates the bypass_egress bit in intrinsic metadata for TNA.
    // Reference: https://github.com/barefootnetworks/Open-Tofino/blob/6a8432eab97bfd1d4805cf24c2c838470840f522/share/p4c/p4include/tofino.p4#L126-L127
    @field_list(PRESERVE_FABRIC_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    bool                      skip_egress;
    @field_list(PRESERVE_FABRIC_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    bool                      do_spgw_uplink_recirc;
    @field_list(PRESERVE_FABRIC_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    bit<1>                    drop_ctl;
    @field_list(PRESERVE_FABRIC_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    bit<3>                    int_mirror_type;
    @field_list(PRESERVE_FABRIC_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    bool                      do_int_mirroring;

    @field_list(PRESERVE_FABRIC_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    fabric_ingress_metadata_t ingress;
    @field_list(PRESERVE_FABRIC_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    fabric_egress_metadata_t  egress;

    @field_list(PRESERVE_STANDARD_MD, PRESERVE_FABRIC_MD_AND_STANDARD_MD)
    v1model_standard_md_t     v1model_standard_md;
}

struct v1model_header_t {
    ingress_headers_t ingress;
    egress_headers_t egress;
}

error {
    PacketRejectedByParser
}

#endif // __HEADER_V1MODEL__
