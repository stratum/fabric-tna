// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __CHECKSUM__
#define __CHECKSUM__

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

control FabricVerifyChecksum(inout v1model_header_t hdr,
                             inout fabric_v1model_metadata_t meta) {
    apply {
        verify_checksum(hdr.ingress.ipv4.isValid(),
            {
                hdr.ingress.ipv4.version,
                hdr.ingress.ipv4.ihl,
                hdr.ingress.ipv4.dscp,
                hdr.ingress.ipv4.ecn,
                hdr.ingress.ipv4.total_len,
                hdr.ingress.ipv4.identification,
                hdr.ingress.ipv4.flags,
                hdr.ingress.ipv4.frag_offset,
                hdr.ingress.ipv4.ttl,
                hdr.ingress.ipv4.protocol,
                hdr.ingress.ipv4.src_addr,
                hdr.ingress.ipv4.dst_addr
            },
            hdr.ingress.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        verify_checksum(hdr.ingress.inner_ipv4.isValid(),
            {
                hdr.ingress.inner_ipv4.version,
                hdr.ingress.inner_ipv4.ihl,
                hdr.ingress.inner_ipv4.dscp,
                hdr.ingress.inner_ipv4.ecn,
                hdr.ingress.inner_ipv4.total_len,
                hdr.ingress.inner_ipv4.identification,
                hdr.ingress.inner_ipv4.flags,
                hdr.ingress.inner_ipv4.frag_offset,
                hdr.ingress.inner_ipv4.ttl,
                hdr.ingress.inner_ipv4.protocol,
                hdr.ingress.inner_ipv4.src_addr,
                hdr.ingress.inner_ipv4.dst_addr
            },
            hdr.ingress.inner_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
#ifdef WITH_INT
        verify_checksum(hdr.egress.report_ipv4.isValid(),
            {
                hdr.egress.report_ipv4.version,
                hdr.egress.report_ipv4.ihl,
                hdr.egress.report_ipv4.dscp,
                hdr.egress.report_ipv4.ecn,
                hdr.egress.report_ipv4.total_len,
                hdr.egress.report_ipv4.identification,
                hdr.egress.report_ipv4.flags,
                hdr.egress.report_ipv4.frag_offset,
                hdr.egress.report_ipv4.ttl,
                hdr.egress.report_ipv4.protocol,
                hdr.egress.report_ipv4.src_addr,
                hdr.egress.report_ipv4.dst_addr
            },
            hdr.egress.report_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
#endif // WITH_INT
    }
}

control FabricComputeChecksum(inout v1model_header_t hdr,
                              inout fabric_v1model_metadata_t fabric_md){
    apply {
        update_checksum(hdr.ingress.ipv4.isValid(),
            {
                hdr.ingress.ipv4.version,
                hdr.ingress.ipv4.ihl,
                hdr.ingress.ipv4.dscp,
                hdr.ingress.ipv4.ecn,
                hdr.ingress.ipv4.total_len,
                hdr.ingress.ipv4.identification,
                hdr.ingress.ipv4.flags,
                hdr.ingress.ipv4.frag_offset,
                hdr.ingress.ipv4.ttl,
                hdr.ingress.ipv4.protocol,
                hdr.ingress.ipv4.src_addr,
                hdr.ingress.ipv4.dst_addr
            },
            hdr.ingress.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        update_checksum(hdr.ingress.inner_ipv4.isValid(),
            {
                hdr.ingress.inner_ipv4.version,
                hdr.ingress.inner_ipv4.ihl,
                hdr.ingress.inner_ipv4.dscp,
                hdr.ingress.inner_ipv4.ecn,
                hdr.ingress.inner_ipv4.total_len,
                hdr.ingress.inner_ipv4.identification,
                hdr.ingress.inner_ipv4.flags,
                hdr.ingress.inner_ipv4.frag_offset,
                hdr.ingress.inner_ipv4.ttl,
                hdr.ingress.inner_ipv4.protocol,
                hdr.ingress.inner_ipv4.src_addr,
                hdr.ingress.inner_ipv4.dst_addr
            },
            hdr.ingress.inner_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
#ifdef WITH_INT
        update_checksum(hdr.egress.report_ipv4.isValid(),
            {
                hdr.egress.report_ipv4.version,
                hdr.egress.report_ipv4.ihl,
                hdr.egress.report_ipv4.dscp,
                hdr.egress.report_ipv4.ecn,
                hdr.egress.report_ipv4.total_len,
                hdr.egress.report_ipv4.identification,
                hdr.egress.report_ipv4.flags,
                hdr.egress.report_ipv4.frag_offset,
                hdr.egress.report_ipv4.ttl,
                hdr.egress.report_ipv4.protocol,
                hdr.egress.report_ipv4.src_addr,
                hdr.egress.report_ipv4.dst_addr
            },
            hdr.egress.report_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
#endif
    }
}

#endif // __CHECKSUM__
