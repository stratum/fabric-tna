// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __CHECKSUM__
#define __CHECKSUM__

#include "../header.p4"
#include "../define.p4"

control FabricVerifyChecksum(inout ingress_headers_t hdr,
                             inout fabric_ingress_metadata_t meta) {
    apply {}
}

control FabricComputeChecksum(inout ingress_headers_t hdr,
                              inout fabric_ingress_metadata_t meta)
{
    apply {}
}

#endif // __CHECKSUM__
