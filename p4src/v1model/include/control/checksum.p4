// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __CHECKSUM__
#define __CHECKSUM__

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

control FabricVerifyChecksum(inout v1model_header_t hdr,
                             inout fabric_v1model_metadata_t meta) {
    apply {
        verify_checksum(hdr.ingress_h.ipv4.isValid(),
            {
                hdr.ingress_h.ipv4.version,
                hdr.ingress_h.ipv4.ihl,
                hdr.ingress_h.ipv4.dscp,
                hdr.ingress_h.ipv4.ecn,
                hdr.ingress_h.ipv4.total_len,
                hdr.ingress_h.ipv4.identification,
                hdr.ingress_h.ipv4.flags,
                hdr.ingress_h.ipv4.frag_offset,
                hdr.ingress_h.ipv4.ttl,
                hdr.ingress_h.ipv4.protocol,
                hdr.ingress_h.ipv4.src_addr,
                hdr.ingress_h.ipv4.dst_addr
            },
            hdr.ingress_h.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        verify_checksum(hdr.egress_h.ipv4.isValid(),
            {
                hdr.egress_h.ipv4.version,
                hdr.egress_h.ipv4.ihl,
                hdr.egress_h.ipv4.dscp,
                hdr.egress_h.ipv4.ecn,
                hdr.egress_h.ipv4.total_len,
                hdr.egress_h.ipv4.identification,
                hdr.egress_h.ipv4.flags,
                hdr.egress_h.ipv4.frag_offset,
                hdr.egress_h.ipv4.ttl,
                hdr.egress_h.ipv4.protocol,
                hdr.egress_h.ipv4.src_addr,
                hdr.egress_h.ipv4.dst_addr
            },
            hdr.egress_h.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

// control FabricComputeChecksum(inout v1model_header_t hdr,
//                               inout fabric_v1model_metadata_t meta){
//     apply {
//         update_checksum(hdr.ingress_h.ipv4.isValid(),
//             {
//                 hdr.ingress_h.ipv4.version,
//                 hdr.ingress_h.ipv4.ihl,
//                 hdr.ingress_h.ipv4.dscp,
//                 hdr.ingress_h.ipv4.ecn,
//                 hdr.ingress_h.ipv4.total_len,
//                 hdr.ingress_h.ipv4.identification,
//                 hdr.ingress_h.ipv4.flags,
//                 hdr.ingress_h.ipv4.frag_offset,
//                 hdr.ingress_h.ipv4.ttl,
//                 hdr.ingress_h.ipv4.protocol,
//                 hdr.ingress_h.ipv4.src_addr,
//                 hdr.ingress_h.ipv4.dst_addr
//             },
//             hdr.ingress_h.ipv4.hdr_checksum,
//             HashAlgorithm.csum16
//         );
//         update_checksum(hdr.egress_h.ipv4.isValid(),
//             {
//                 hdr.egress_h.ipv4.version,
//                 hdr.egress_h.ipv4.ihl,
//                 hdr.egress_h.ipv4.dscp,
//                 hdr.egress_h.ipv4.ecn,
//                 hdr.egress_h.ipv4.total_len,
//                 hdr.egress_h.ipv4.identification,
//                 hdr.egress_h.ipv4.flags,
//                 hdr.egress_h.ipv4.frag_offset,
//                 hdr.egress_h.ipv4.ttl,
//                 hdr.egress_h.ipv4.protocol,
//                 hdr.egress_h.ipv4.src_addr,
//                 hdr.egress_h.ipv4.dst_addr
//             },
//             hdr.egress_h.ipv4.hdr_checksum,
//             HashAlgorithm.csum16
//         );
// #ifdef WITH_SPGW
//         update_checksum(hdr.egress_h.outer_ipv4.isValid(),
//             {
//                 hdr.egress_h.outer_ipv4.version,
//                 hdr.egress_h.outer_ipv4.ihl,
//                 hdr.egress_h.outer_ipv4.dscp,
//                 hdr.egress_h.outer_ipv4.ecn,
//                 hdr.egress_h.outer_ipv4.total_len,
//                 hdr.egress_h.outer_ipv4.identification,
//                 hdr.egress_h.outer_ipv4.flags,
//                 hdr.egress_h.outer_ipv4.frag_offset,
//                 hdr.egress_h.outer_ipv4.ttl,
//                 hdr.egress_h.outer_ipv4.protocol,
//                 hdr.egress_h.outer_ipv4.src_addr,
//                 hdr.egress_h.outer_ipv4.dst_addr
//             },
//             hdr.egress_h.outer_ipv4.hdr_checksum,
//             HashAlgorithm.csum16
//         );
// #endif // WITH_SPGW
//     }
// }

#endif // __CHECKSUM__
