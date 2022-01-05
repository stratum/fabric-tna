// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0


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
#ifdef WITH_SPGW
#include "v1model/include/control/spgw.p4"
#endif // WITH_SPGW
#ifdef WITH_INT
#include "v1model/include/control/int.p4"
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
#ifdef WITH_SPGW
    SpgwIngress() spgw;
#endif // WITH_SPGW
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
// #ifdef WITH_LATEST_P4C
//         if (standard_md.instance_type == 0 ) {
//             // Packet was not recirculated or cloned -> save standard_metadata in custom struct to preserve it.
//             fabric_md.v1model_standard_md.ingress_port = standard_md.ingress_port;
//             fabric_md.v1model_standard_md.egress_port = standard_md.egress_port;
//             fabric_md.v1model_standard_md.egress_spec = standard_md.egress_spec;
//         }

//         if (standard_md.instance_type != 0) {
//             // restore preserved metadata
//             standard_md.ingress_port = fabric_md.v1model_standard_md.ingress_port;
//         }
// #endif //WITH_LATEST_P4C

        if (IS_RECIRCULATED(standard_md)) {
            // After recirculation is performed, override ingress port to match TNA recirc port.
            // This workaround allows to have the same PTF structure, avoid inserting new entries to tables.
            standard_md.ingress_port = DROP_OVERRIDE_FAKE_PORT; // emulates TNA recirc port
        }

        lkp_md_init.apply(hdr.ingress, fabric_md.ingress.lkp);
        pkt_io.apply(hdr.ingress, fabric_md.ingress, fabric_md.skip_egress ,standard_md);
#ifdef WITH_INT
        int_watchlist.apply(hdr.ingress, fabric_md.ingress, standard_md);
#endif // WITH_INT
        stats.apply(fabric_md.ingress.lkp, standard_md.ingress_port,
            fabric_md.ingress.bridged.base.stats_flow_id);

        slice_tc_classifier.apply(hdr.ingress, standard_md, fabric_md.ingress);
        filtering.apply(hdr.ingress, fabric_md.ingress, standard_md);
#ifdef WITH_SPGW
        if (!fabric_md.ingress.skip_forwarding) {
            spgw.apply(hdr.ingress, fabric_md, standard_md);
        }
#endif // WITH_SPGW
        if (!fabric_md.ingress.skip_forwarding) {
            forwarding.apply(hdr.ingress, fabric_md, standard_md);
        }
        hasher.apply(hdr.ingress, fabric_md.ingress);
        if (!fabric_md.ingress.skip_next) {
            pre_next.apply(hdr.ingress, fabric_md.ingress);
        }
        acl.apply(hdr.ingress, fabric_md, standard_md);
        if (!fabric_md.ingress.skip_next) {
            next.apply(hdr.ingress, fabric_md, standard_md);
        }
        qos.apply(fabric_md, standard_md);
#ifdef WITH_INT
        // Should always apply last to guarantee generation of drop reports.
        int_ingress.apply(hdr.ingress, fabric_md, standard_md);
#endif // WITH_INT

        // Emulating TNA behavior through bridged metadata.
        fabric_md.egress.bridged = fabric_md.ingress.bridged;
    }
}

control FabricEgress (inout v1model_header_t hdr,
                      inout fabric_v1model_metadata_t fabric_md,
                      inout standard_metadata_t standard_md) {

    StatsEgress() stats;
    PacketIoEgress() pkt_io_egress;
    EgressNextControl() egress_next;
    EgressDscpRewriter() dscp_rewriter;
#ifdef WITH_SPGW
    SpgwEgress() spgw;
#endif // WITH_SPGW
#ifdef WITH_INT
    IntEgressParserEmulator() parser_emulator;
    IntEgress() int_egress;
#endif // WITH_INT

    apply {
        // Setting other fields in egress metadata, related to TNA's FabricEgressParser.
        fabric_md.egress.cpu_port = 0;

#ifdef WITH_INT
        if ((bit<8>)fabric_md.egress.bridged.int_bmd.report_type == BridgedMdType_t.INT_INGRESS_DROP){
            // Ingress drops become themselves a report. Mirroring is not performed.
            fabric_md.egress.is_int_recirc = true;
            parser_emulator.apply(hdr, fabric_md, standard_md);
#ifdef WITH_LATEST_P4C
            recirculate_preserving_field_list(PRESERVE_STANDARD_MD);
#else
            recirculate({});
#endif // WITH_LATEST_P4C
        }

        // if (IS_E2E_CLONE(standard_md)) {
               // NOT IMPLEMENTED.
        //     // Mirrored packet that will be transformed in report. needed for EgressDropReport.
        //     parser_emulator.apply(hdr, fabric_md, standard_md);
        //     recirculate(standard_md);
        // }
#endif // WITH_INT

        if (fabric_md.skip_egress){
            exit;
        }

        pkt_io_egress.apply(hdr.ingress, fabric_md.egress ,standard_md);
        stats.apply(fabric_md.egress.bridged.base.stats_flow_id, standard_md.egress_port,
             fabric_md.egress.bridged.bmd_type);
        egress_next.apply(hdr.ingress, fabric_md, standard_md);
#ifdef WITH_SPGW
        spgw.apply(hdr.ingress, fabric_md);
#endif // WITH_SPGW
#ifdef WITH_INT
        int_egress.apply(hdr, fabric_md, standard_md);
#endif // WITH_INT
        dscp_rewriter.apply(fabric_md, standard_md, hdr.ingress);

        if (fabric_md.do_spgw_uplink_recirc) {
            // Recirculate UE-to-UE traffic.
#ifdef WITH_LATEST_P4C
            recirculate_preserving_field_list(PRESERVE_STANDARD_MD);
#else
            recirculate(standard_md);
#endif // WITH_LATEST_P4C
        }

        if (fabric_md.drop_ctl == 1) {
            // NOTE: for INT, if ingress_port is not overriden in Ingress to match one of the recirc_ports,
            // the report will miss egress.next leading to a drop here.
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
