// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0


#ifndef V1MODEL
#define V1MODEL
#endif

#include <core.p4>
#include <v1model.p4>

#include "shared/size.p4"
#include "v1model/include/define_v1model.p4" // shared/define.p4 included in define_v1model.p4
#include "v1model/include/header_v1model.p4"
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
#ifdef WITH_UPF
#include "v1model/include/control/upf.p4"
#endif // WITH_UPF
#ifdef WITH_INT
#include "v1model/include/control/int.p4"
#include "v1model/include/control/int_tna_parser_emulator.p4"
#endif // WITH_INT

control FabricIngress (inout v1model_header_t hdr,
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
#ifdef WITH_UPF
    UpfIngress() upf;
#endif // WITH_UPF
#ifdef WITH_INT
    IntWatchlist() int_watchlist;
    IntIngress() int_ingress;
#endif // WITH_INT

    apply {
        // Override default egress port 0 which has an undefined behavior.
        // for more information see https://github.com/p4lang/behavioral-model/issues/992
        mark_to_drop(standard_md);
        if (standard_md.parser_error == error.PacketRejectedByParser) {
            // packet was rejected by parser -> drop.
            exit;
        }

        if (IS_RECIRCULATED(standard_md)) {
            // After recirculation is performed, override ingress port, emulating TNA recirc port.
            // This workaround allows to have the same PTF structure.
            fabric_md.ingress.bridged.base.ig_port = FAKE_V1MODEL_RECIRC_PORT;
        }

        lkp_md_init.apply(hdr.ingress, fabric_md.ingress.lkp);
        pkt_io.apply(hdr.ingress, fabric_md.ingress, fabric_md.skip_egress, standard_md, fabric_md.recirc_preserved_egress_port);
#ifdef WITH_INT
        int_watchlist.apply(hdr.ingress, fabric_md.ingress, standard_md, fabric_md.recirc_preserved_report_type);
#endif // WITH_INT
        stats.apply(fabric_md.ingress.lkp, fabric_md.ingress.bridged.base.ig_port,
            fabric_md.ingress.bridged.base.stats_flow_id);

        slice_tc_classifier.apply(hdr.ingress, standard_md, fabric_md.ingress);
        filtering.apply(hdr.ingress, fabric_md.ingress, standard_md);
#ifdef WITH_UPF
        if (!fabric_md.ingress.skip_forwarding) {
            upf.apply(hdr.ingress, fabric_md.ingress, standard_md, fabric_md.do_upf_uplink_recirc, fabric_md.drop_ctl);
        }
#endif // WITH_UPF
        if (!fabric_md.ingress.skip_forwarding) {
            forwarding.apply(hdr.ingress, fabric_md.ingress, standard_md, fabric_md.drop_ctl);
        }
        hasher.apply(hdr.ingress, fabric_md.ingress);
        if (!fabric_md.ingress.skip_next) {
            pre_next.apply(hdr.ingress, fabric_md.ingress);
        }
        acl.apply(hdr.ingress, fabric_md.ingress, standard_md, fabric_md.recirc_preserved_egress_port, fabric_md.drop_ctl);
        if (!fabric_md.ingress.skip_next) {
            next.apply(hdr.ingress, fabric_md.ingress, standard_md, fabric_md.recirc_preserved_egress_port);
        }
        qos.apply(fabric_md.ingress, standard_md, fabric_md.drop_ctl);
#ifdef WITH_INT
        // Should always apply last to guarantee generation of drop reports.
        int_ingress.apply(hdr.ingress, fabric_md.ingress, standard_md, fabric_md.drop_ctl);
#endif // WITH_INT

        // Emulating TNA behavior through bridged metadata.
        fabric_md.egress.bridged = fabric_md.ingress.bridged;

        // Ensure to drop traffic in the ingress pipe when required
        if (fabric_md.drop_ctl == 1) {
            mark_to_drop(standard_md);
        }
    }
}

control FabricEgress (inout v1model_header_t hdr,
                      inout fabric_v1model_metadata_t fabric_md,
                      inout standard_metadata_t standard_md) {

    StatsEgress() stats;
    PacketIoEgress() pkt_io_egress;
    EgressNextControl() egress_next;
    EgressDscpRewriter() dscp_rewriter;
#ifdef WITH_UPF
    UpfEgress() upf;
#endif // WITH_UPF
#ifdef WITH_INT
    IntTnaEgressParserEmulator() parser_emulator;
    IntEgress() int_egress;
#endif // WITH_INT

    apply {
        // Setting other fields in egress metadata, related to TNA's FabricEgressParser.
        fabric_md.egress.cpu_port = 0;

        if (fabric_md.skip_egress){
            exit;
        }

#ifdef WITH_INT
        if (IS_E2E_CLONE(standard_md)) {
            // Packet must generate the flow report or is an egress drop.

            // Restore preserved metadata.
            fabric_md.egress.bridged.int_bmd.drop_reason = fabric_md.recirc_preserved_drop_reason;
            fabric_md.egress.bridged.int_bmd.report_type = fabric_md.recirc_preserved_report_type;

            parser_emulator.apply(hdr, fabric_md.egress, standard_md);
        }

       if ((bit<8>)fabric_md.egress.bridged.int_bmd.report_type == BridgedMdType_t.INT_INGRESS_DROP){
            // Ingress drops become themselves a report. Mirroring is not performed.
            parser_emulator.apply(hdr, fabric_md.egress, standard_md);
        }
#endif // WITH_INT

        pkt_io_egress.apply(hdr.ingress, fabric_md.egress ,standard_md, fabric_md.recirc_preserved_ingress_port);
        stats.apply(fabric_md.egress.bridged.base.stats_flow_id, standard_md.egress_port,
             fabric_md.egress.bridged.bmd_type);
        egress_next.apply(hdr.ingress, fabric_md.egress, standard_md, fabric_md.recirc_preserved_drop_reason, fabric_md.drop_ctl);
#ifdef WITH_UPF
        upf.apply(hdr.ingress, fabric_md.egress);
#endif // WITH_UPF
#ifdef WITH_INT
        int_egress.apply(hdr, fabric_md, standard_md);
#endif // WITH_INT
        dscp_rewriter.apply(fabric_md.egress, standard_md, hdr.ingress);

        if (fabric_md.do_upf_uplink_recirc) {
            // Recirculate UE-to-UE traffic.
            recirculate_preserving_field_list(NO_PRESERVATION);
        }

        if (fabric_md.drop_ctl == 1) {
            mark_to_drop(standard_md);
        }
    } // end of apply{}
}

V1Switch(
    FabricParser(),
    FabricVerifyChecksum(),
    FabricIngress(),
    FabricEgress(),
    FabricComputeChecksum(),
    FabricDeparser()
) main;
