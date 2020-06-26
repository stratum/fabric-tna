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
    Acl() acl;

    apply {
        pkt_io_ingress.apply(hdr, fabric_md, ig_tm_md);
        filtering.apply(hdr, fabric_md, ig_intr_md);
        acl.apply(hdr, fabric_md, ig_intr_md, ig_dprsr_md, ig_tm_md);

        // Send to loopback port of odd pipe (0->1, 2->3).
        if (ig_dprsr_md.drop_ctl != 1 && ig_tm_md.ucast_egress_port != CPU_PORT) {
            ig_tm_md.ucast_egress_port = 0x80 | ig_intr_md.ingress_port;
        }

        if (ig_tm_md.bypass_egress == 1w0) {
            hdr.bridge_md.setValid();
            hdr.bridge_md.is_multicast = fabric_md.is_multicast;
            hdr.bridge_md.ingress_port = ig_intr_md.ingress_port;
            hdr.bridge_md.ip_eth_type = fabric_md.ip_eth_type;
            hdr.bridge_md.ip_proto = fabric_md.ip_proto;
            hdr.bridge_md.mpls_label = fabric_md.mpls_label;
            hdr.bridge_md.mpls_ttl = fabric_md.mpls_ttl;
            hdr.bridge_md.vlan_id = fabric_md.vlan_id;
            hdr.bridge_md.skip_forwarding = fabric_md.skip_forwarding;
            hdr.bridge_md.skip_next = fabric_md.skip_next;
            hdr.bridge_md.fwd_type = fabric_md.fwd_type;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
            hdr.bridge_md.push_double_vlan = fabric_md.push_double_vlan;
            hdr.bridge_md.inner_vlan_id = fabric_md.inner_vlan_id;
#endif // WITH_DOUBLE_VLAN_TERMINATION
        }
    }
}

control FabricEgressB(
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    /* TNA */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md) {
    apply {}
}

control FabricIngressB(
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md,
    /* TNA */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md) {

    Forwarding() forwarding;
    Next() next;

    apply {
        if (!fabric_md.skip_forwarding) {
           forwarding.apply(hdr, ig_dprsr_md, fabric_md);
        }
        if (!fabric_md.skip_next) {
            next.apply(hdr, fabric_md, ig_intr_md, ig_tm_md);
        }

        if (ig_tm_md.bypass_egress == 1w0) {
            hdr.bridge_md.setValid();
            hdr.bridge_md.is_multicast = fabric_md.is_multicast;
            hdr.bridge_md.ingress_port = fabric_md.ingress_port;
            hdr.bridge_md.ip_eth_type = fabric_md.ip_eth_type;
            hdr.bridge_md.ip_proto = fabric_md.ip_proto;
            hdr.bridge_md.mpls_label = fabric_md.mpls_label;
            hdr.bridge_md.mpls_ttl = fabric_md.mpls_ttl;
            hdr.bridge_md.vlan_id = fabric_md.vlan_id;
        }
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

    apply {
        pkt_io_egress.apply(hdr, fabric_md, eg_intr_md);
        egress_next.apply(hdr, fabric_md, eg_intr_md, eg_dprsr_md);
    }
}

// Packet comes into ingress profile_a. The packet travels to egress profile_b, then to
// ingress profile_b and finally to egress profile_a.

// Packet flow: -> ingress_a --TM--> egress_b --+ (loopback)
//              <- egress_a <--TM-- ingress_b <-+

// For tofino model:
// --int-port-loop=<pipe_bitmap> (0xA)

Pipeline(
    // ingress_a
    FabricIngressParser(),
    FabricIngress(),
    FabricIngressDeparser(),
    // egress_a
    FabricEgressParser(),
    FabricEgress(),
    FabricEgressDeparser()
) pipeline_profile_a;

Pipeline(
    // ingress_b
    FabricIngressParserB(),
    FabricIngressB(),
    FabricIngressDeparser(),
    // egress_b (empty)
    FabricEgressParserB(),
    FabricEgressB(),
    FabricEgressDeparserB()
) pipeline_profile_b;

Switch(pipeline_profile_a, pipeline_profile_b) main;
