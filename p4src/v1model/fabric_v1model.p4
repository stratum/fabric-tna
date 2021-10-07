// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0


#ifndef V1MODEL
#define V1MODEL
#endif

#include <core.p4>
#include <v1model.p4>

#include "shared/size.p4"
#include "shared/define.p4"
#include "shared/header.p4"
#include "v1model/include/parser.p4"
#include "v1model/include/control/acl.p4"
#include "v1model/include/control/next.p4"
#include "v1model/include/control/stats.p4"
#include "v1model/include/control/hasher.p4"
#include "v1model/include/control/slicing.p4"
#include "v1model/include/control/checksum.p4"
#include "v1model/include/control/packetio.p4"
#include "v1model/include/control/pre_next.p4"
#include "v1model/include/control/filtering.p4"
#include "v1model/include/control/forwarding.p4"
#include "v1model/include/control/lookup_md_init.p4"

control FabricIngress (inout ingress_headers_t hdr,
                       inout fabric_ingress_metadata_t fabric_md,
                       inout standard_metadata_t standard_md) {

    LookupMdInit() lkp_md_init;
    StatsIngress() stats;
    PacketIoIngress() pkt_io;
    Filtering() filtering;
    Forwarding() forwarding;
    PreNext() pre_next;
    Acl() acl;
    Next() next;
    Hasher() hasher;
    IngressSliceTcClassifier() slice_tc_classifier;
    IngressQos() qos;

    apply {
        lkp_md_init.apply(hdr, fabric_md.lkp);
        pkt_io.apply(hdr, fabric_md, standard_md);
        stats.apply(fabric_md.lkp, standard_md.ingress_port,
            fabric_md.bridged.base.stats_flow_id);

        slice_tc_classifier.apply(hdr, standard_md, fabric_md);
        filtering.apply(hdr, fabric_md, standard_md);

        
        if (!fabric_md.skip_forwarding) {
            forwarding.apply(hdr, fabric_md);
        }

        hasher.apply(hdr, fabric_md);
        
        if (!fabric_md.skip_next) {
            pre_next.apply(hdr, fabric_md);
        }

        acl.apply(hdr, fabric_md, standard_md);

        if (!fabric_md.skip_next) {
            next.apply(hdr, fabric_md, standard_md);
        }
        qos.apply(fabric_md, standard_md);
    }
}

control FabricEgress (inout ingress_headers_t hdr,
                      inout fabric_ingress_metadata_t fabric_md,
                      inout standard_metadata_t standard_md) {

    StatsEgress() stats;
    PacketIoEgress() pkt_io_egress;
    EgressNextControl() egress_next;
    EgressDscpRewriter() dscp_rewriter;

    apply {
        pkt_io_egress.apply(hdr, fabric_md, standard_md);
        stats.apply(fabric_md.bridged.base.stats_flow_id, standard_md.egress_port,
             fabric_md.bridged.bmd_type);
        egress_next.apply(hdr, fabric_md, standard_md);
        dscp_rewriter.apply(fabric_md, standard_md, hdr);
    }
}

V1Switch(
    FabricParser(),
    FabricVerifyChecksum(),
    FabricIngress(),
    FabricEgress(),
    FabricComputeChecksum(),
    FabricDeparser()
) main;
