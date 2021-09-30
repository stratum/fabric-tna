// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0


#ifndef TARGET_V1MODEL
#define TARGET_V1MODEL
#endif

#include <core.p4>
#include <v1model.p4>

#include "shared/size.p4"
#include "shared/define.p4"
#include "shared/header.p4"
#include "v1model/include/parser.p4"
#include "v1model/include/control/checksum.p4"

control FabricIngress (inout ingress_headers_t hdr,
                       inout fabric_ingress_metadata_t fabric_metadata,
                       inout standard_metadata_t standard_metadata) {

    apply{}
}

control FabricEgress (inout ingress_headers_t hdr,
                      inout fabric_ingress_metadata_t fabric_metadata,
                      inout standard_metadata_t standard_metadata) {
    apply{}
}

V1Switch(
    FabricParser(),
    FabricVerifyChecksum(),
    FabricIngress(),
    FabricEgress(),
    FabricComputeChecksum(),
    FabricDeparser()
) main;
