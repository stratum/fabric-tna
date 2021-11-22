// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __CHECKSUM__
#define __CHECKSUM__

#include "shared/header.p4"
#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

control FabricVerifyChecksum(inout ingress_headers_t hdr,
                             inout fabric_v1model_metadata_t meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        verify_checksum(hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

control FabricComputeChecksum(inout ingress_headers_t hdr,
                              inout fabric_v1model_metadata_t fabric_md){
    apply {
        update_checksum(hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        update_checksum(hdr.inner_ipv4.isValid(),
            {
                hdr.inner_ipv4.version,
                hdr.inner_ipv4.ihl,
                hdr.inner_ipv4.dscp,
                hdr.inner_ipv4.ecn,
                hdr.inner_ipv4.total_len,
                hdr.inner_ipv4.identification,
                hdr.inner_ipv4.flags,
                hdr.inner_ipv4.frag_offset,
                hdr.inner_ipv4.ttl,
                hdr.inner_ipv4.protocol,
                hdr.inner_ipv4.src_addr,
                hdr.inner_ipv4.dst_addr
            },
            hdr.inner_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

#endif // __CHECKSUM__
