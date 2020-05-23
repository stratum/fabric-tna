// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include <core.p4>
#include <tna.p4>

#include "include/define.p4"
#include "include/size.p4"
#include "include/header.p4"
#include "include/parser.p4"
#include "include/control/packetio.p4"
#include "include/control/filtering.p4"
#include "include/control/forwarding.p4"
#include "include/control/acl.p4"
#include "include/control/next.p4"
// #include "include/checksum.p4"

control FabricIngress (
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    inout fabric_metadata_t fabric_metadata,
    /* TNA */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md) {

    PacketIoIngress() pkt_io_ingress;
    Filtering() filtering;
    Forwarding() forwarding;
    Acl() acl;
    Next() next;

    apply {
        pkt_io_ingress.apply(hdr, fabric_metadata, ig_tm_md);
        filtering.apply(hdr, fabric_metadata, ig_intr_md);
        if (!fabric_metadata.ctrl.skip_forwarding) {
           forwarding.apply(hdr, fabric_metadata);
        }
        acl.apply(hdr, fabric_metadata, ig_intr_md, ig_dprsr_md, ig_tm_md);
        if (!fabric_metadata.ctrl.skip_next) {
            next.apply(hdr, fabric_metadata, ig_intr_md, ig_tm_md);
        }
    }
}

control FabricEgress (
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    inout fabric_metadata_t fabric_metadata,
    /* TNA */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md) {

    PacketIoEgress() pkt_io_egress;
    EgressNextControl() egress_next;

    apply {
        pkt_io_egress.apply(hdr, fabric_metadata, eg_intr_md);
        egress_next.apply(hdr, fabric_metadata, eg_intr_md, eg_dprsr_md);
    }
}

Pipeline(
    FabricIngressParser(),
    FabricIngress(),
    FabricIngressDeparser(),
    FabricEgressParser(),
    FabricEgress(),
    FabricEgressDeparser()
) pipe;

Switch(pipe) main;
