// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

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
    bool                      do_upf_uplink_recirc;
    // The drop_ctl emulates the drop_ctl bit in intrinsic metadata for TNA.
    bit<1>                    drop_ctl;
    // The int_mirror_type emulates the mirror_type flag in ingress_intrinsic_metadata_for_deparser_t.
    IntReportType_t           int_mirror_type;

    fabric_ingress_metadata_t ingress;
    fabric_egress_metadata_t  egress;

    // Needed for Egress INT reports (drop or flow)
    // The following fields are preserved when recirculating or cloning the packet.
    // Find out how field_lists work reading the example in v1model.p4 : https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4
    @field_list(PRESERVE_INT_MD)
    IntReportType_t  recirc_preserved_report_type;
    @field_list(PRESERVE_INT_MD)
    FabricPortId_t   recirc_preserved_egress_port;
    @field_list(PRESERVE_INT_MD)
    IntDropReason_t  recirc_preserved_drop_reason;

    // Needed for Packet-INs
    @field_list(PRESERVE_INGRESS_PORT)
    FabricPortId_t   recirc_preserved_ingress_port;
}

struct v1model_header_t {
    ingress_headers_t ingress;
    egress_headers_t egress;
}

error {
    PacketRejectedByParser
}

#endif // __HEADER_V1MODEL__
