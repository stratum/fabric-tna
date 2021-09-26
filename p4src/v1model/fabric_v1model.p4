// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>
#include <v1model.p4>

#include "include/size.p4"
#include "include/header.p4"
#include "include/parser.p4"
#include "include/control/checksum.p4"

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
