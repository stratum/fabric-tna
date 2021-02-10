// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

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
#include "include/control/hasher.p4"
#ifdef WITH_SPGW
#include "include/control/spgw.p4"
#endif // WITH_SPGW
#ifdef WITH_INT
#include "include/control/int.p4"
#endif

control FabricIngress (
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md,
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
    Hasher() hasher;
#ifdef WITH_SPGW
    SpgwIngress() spgw;
#endif // WITH_SPGW
#ifdef WITH_INT
    IntIngress() int_ingress;
#endif // WITH_INT

    apply {
        pkt_io_ingress.apply(hdr, fabric_md, ig_intr_md, ig_tm_md, ig_dprsr_md);
#ifdef WITH_SPGW
        spgw.apply(hdr, fabric_md, ig_dprsr_md, ig_tm_md);
#endif // WITH_SPGW
        filtering.apply(hdr, fabric_md, ig_intr_md);
        if (!fabric_md.skip_forwarding) {
            forwarding.apply(hdr, fabric_md);
        }
        hasher.apply(hdr, fabric_md);
        acl.apply(hdr, fabric_md, ig_intr_md, ig_dprsr_md, ig_tm_md);
        if (!fabric_md.skip_next) {
            next.apply(hdr, fabric_md, ig_intr_md, ig_tm_md);
        }
#ifdef WITH_INT
        int_ingress.apply(hdr, fabric_md, ig_intr_md);
#endif // WITH_INT
    }
}

control FabricEgress (
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    /* TNA */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md) {

    PacketIoEgress() pkt_io_egress;
    EgressNextControl() egress_next;
#ifdef WITH_SPGW
    SpgwEgress() spgw;
#endif // WITH_SPGW
#ifdef WITH_INT
    IntEgress() int_egress;
#endif // WITH_INT

    apply {
#ifdef WITH_INT
        // FIXME: Parser wrongly extracts stuff on the validity bits (POVs) of
        // INT report headers. Without this workaround, such POVs share a PHV
        // container with a bridged md field. When parser extracts bridged md,
        // POVs get written by values adjacent to the extracted bridged md
        // field. Using @pa_no_overlay for POVs doesn't have any effect.
        // According to BA-1141, POVs are never shared... is this a compiler
        // bug? Calling setInvalid() causes the compiler to allocate these 4
        // POVs on a non-shared container, but it burns stage 0 for the INT
        // report generation path (not a big deal).
        hdr.report_ethernet.setInvalid();
        hdr.report_eth_type.setInvalid();
        hdr.report_ipv4.setInvalid();
        hdr.report_udp.setInvalid();
#endif // WITH_INT
        pkt_io_egress.apply(hdr, fabric_md, eg_intr_md);
#ifdef WITH_INT
        int_egress.apply(hdr, fabric_md, eg_intr_md, eg_prsr_md, eg_dprsr_md);
#endif
        egress_next.apply(hdr, fabric_md, eg_intr_md, eg_dprsr_md);
#ifdef WITH_SPGW
        spgw.apply(hdr, fabric_md);
#endif // WITH_SPGW
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
