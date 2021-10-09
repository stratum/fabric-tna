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
                       inout fabric_v1model_metadata_t fabric_md,
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
        fabric_ingress_metadata_t ingress_md = fabric_md.ingress_md;

        if (standard_md.parser_error == error.PacketRejectedByParser) {
            // packet was rejected by parser -> drop.
            mark_to_drop(standard_md);
            exit;
        }

        lkp_md_init.apply(hdr, ingress_md.lkp);
        pkt_io.apply(hdr, ingress_md, standard_md);
        stats.apply(ingress_md.lkp, standard_md.ingress_port,
            ingress_md.bridged.base.stats_flow_id);

        slice_tc_classifier.apply(hdr, standard_md, ingress_md);
        filtering.apply(hdr, ingress_md, standard_md);

        
        if (!ingress_md.skip_forwarding) {
            forwarding.apply(hdr, ingress_md);
        }

        hasher.apply(hdr, ingress_md);
        
        if (!ingress_md.skip_next) {
            pre_next.apply(hdr, ingress_md);
        }

        acl.apply(hdr, ingress_md, standard_md);

        if (!ingress_md.skip_next) {
            next.apply(hdr, ingress_md, standard_md);
        }
        qos.apply(ingress_md, standard_md);

        // Emulating TNA behavior through bridged metadata.
        fabric_md.egress_md.bridged = ingress_md.bridged;
    }
}

control FabricEgress (inout ingress_headers_t hdr,
                      inout fabric_v1model_metadata_t fabric_md,
                      inout standard_metadata_t standard_md) {

    StatsEgress() stats;
    PacketIoEgress() pkt_io_egress;
    EgressNextControl() egress_next;
    EgressDscpRewriter() dscp_rewriter;

    apply {
        fabric_egress_metadata_t egress_md = fabric_md.egress_md;

        pkt_io_egress.apply(hdr, egress_md, standard_md);
        stats.apply(egress_md.bridged.base.stats_flow_id, standard_md.egress_port,
             egress_md.bridged.bmd_type);
        egress_next.apply(hdr, egress_md, standard_md);
        dscp_rewriter.apply(egress_md, standard_md, hdr);
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
