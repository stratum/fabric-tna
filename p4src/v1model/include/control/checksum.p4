// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __CHECKSUM__
#define __CHECKSUM__

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

control FabricVerifyChecksum(inout v1model_header_t hdr,
                             inout fabric_v1model_metadata_t meta) {
    apply {
        verify_checksum(hdr.ig.ipv4.isValid(),
            {
                hdr.ig.ipv4.version,
                hdr.ig.ipv4.ihl,
                hdr.ig.ipv4.dscp,
                hdr.ig.ipv4.ecn,
                hdr.ig.ipv4.total_len,
                hdr.ig.ipv4.identification,
                hdr.ig.ipv4.flags,
                hdr.ig.ipv4.frag_offset,
                hdr.ig.ipv4.ttl,
                hdr.ig.ipv4.protocol,
                hdr.ig.ipv4.src_addr,
                hdr.ig.ipv4.dst_addr
            },
            hdr.ig.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        verify_checksum(hdr.ig.ipv4.isValid(),
            {
                hdr.ig.ipv4.version,
                hdr.ig.ipv4.ihl,
                hdr.ig.ipv4.dscp,
                hdr.ig.ipv4.ecn,
                hdr.ig.ipv4.total_len,
                hdr.ig.ipv4.identification,
                hdr.ig.ipv4.flags,
                hdr.ig.ipv4.frag_offset,
                hdr.ig.ipv4.ttl,
                hdr.ig.ipv4.protocol,
                hdr.ig.ipv4.src_addr,
                hdr.ig.ipv4.dst_addr
            },
            hdr.ig.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

control FabricComputeChecksum(inout v1model_header_t hdr,
                              inout fabric_v1model_metadata_t fabric_md){
    apply {
        update_checksum(hdr.ig.ipv4.isValid(),
            {
                hdr.ig.ipv4.version,
                hdr.ig.ipv4.ihl,
                hdr.ig.ipv4.dscp,
                hdr.ig.ipv4.ecn,
                hdr.ig.ipv4.total_len,
                hdr.ig.ipv4.identification,
                hdr.ig.ipv4.flags,
                hdr.ig.ipv4.frag_offset,
                hdr.ig.ipv4.ttl,
                hdr.ig.ipv4.protocol,
                hdr.ig.ipv4.src_addr,
                hdr.ig.ipv4.dst_addr
            },
            hdr.ig.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        update_checksum(hdr.ig.inner_ipv4.isValid(),
            {
                hdr.ig.inner_ipv4.version,
                hdr.ig.inner_ipv4.ihl,
                hdr.ig.inner_ipv4.dscp,
                hdr.ig.inner_ipv4.ecn,
                hdr.ig.inner_ipv4.total_len,
                hdr.ig.inner_ipv4.identification,
                hdr.ig.inner_ipv4.flags,
                hdr.ig.inner_ipv4.frag_offset,
                hdr.ig.inner_ipv4.ttl,
                hdr.ig.inner_ipv4.protocol,
                hdr.ig.inner_ipv4.src_addr,
                hdr.ig.inner_ipv4.dst_addr
            },
            hdr.ig.inner_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

#endif // __CHECKSUM__
