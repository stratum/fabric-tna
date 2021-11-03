// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0


#ifndef V1MODEL
#define V1MODEL
#endif

#include <core.p4>
#include <v1model.p4>

#include "shared/size.p4"
#include "v1model/include/define_v1model.p4" // shared/define.p4 included in define_v1model.p4
#include "v1model/include/header_v1model.p4" // shared/header.p4 included in header_v1model.p4
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
#endif

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

    apply {
        if (standard_md.parser_error == error.PacketRejectedByParser) {
            // packet was rejected by parser -> drop.
            mark_to_drop(standard_md);
            exit;
        }

        lkp_md_init.apply(hdr.ingress_h, fabric_md.ingress.lkp);
        pkt_io.apply(hdr.ingress_h, fabric_md.ingress, fabric_md.skip_egress ,standard_md);
        stats.apply(fabric_md.ingress.lkp, standard_md.ingress_port,
            fabric_md.ingress.bridged.base.stats_flow_id);

        slice_tc_classifier.apply(hdr.ingress_h, standard_md, fabric_md.ingress);
        filtering.apply(hdr.ingress_h, fabric_md.ingress, standard_md);
#ifdef WITH_SPGW
        if (!fabric_md.ingress.skip_forwarding) {
            spgw.apply(hdr.ingress_h, fabric_md.ingress, standard_md);
        }
#endif // WITH_SPGW
        if (!fabric_md.ingress.skip_forwarding) {
            forwarding.apply(hdr.ingress_h, fabric_md.ingress);
        }
        hasher.apply(hdr.ingress_h, fabric_md.ingress);
        if (!fabric_md.ingress.skip_next) {
            pre_next.apply(hdr.ingress_h, fabric_md.ingress);
        }
        acl.apply(hdr.ingress_h, fabric_md.ingress, standard_md);
        if (!fabric_md.ingress.skip_next) {
            next.apply(hdr.ingress_h, fabric_md.ingress, standard_md);
        }
        qos.apply(fabric_md.ingress, standard_md);

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

    table debug {
            key = {
                hdr.egress_h.outer_ipv4.src_addr : exact;
                hdr.egress_h.outer_ipv4.dst_addr : exact;
                hdr.egress_h.outer_ipv4.version  : exact;
            }
            actions = {
                nop;
            }
            default_action = nop();
            const size = 1;
    }

    apply {
        // Setting other fields in egress metadata, related to TNA's FabricEgressParser.
        fabric_md.egress.cpu_port = 0;
        fabric_md.egress.pkt_length = (bit<16>) standard_md.packet_length;

        hdr.egress_h.packet_in = hdr.ingress_h.packet_in;
        hdr.egress_h.fake_ethernet = hdr.ingress_h.fake_ethernet;
        hdr.egress_h.ethernet = hdr.ingress_h.ethernet;
        hdr.egress_h.vlan_tag = hdr.ingress_h.vlan_tag;
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
        hdr.egress_h.inner_vlan_tag = hdr.ingress_h.inner_vlan_tag;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
        hdr.egress_h.eth_type = hdr.ingress_h.eth_type;
        hdr.egress_h.mpls = hdr.ingress_h.mpls;
        hdr.egress_h.ipv4 = hdr.ingress_h.ipv4;
        hdr.egress_h.ipv6 = hdr.ingress_h.ipv6;
        hdr.egress_h.udp = hdr.ingress_h.udp;

        // Performing logic for Deparser (if statements are not supported within deparser on target bmv2.)
        if (!hdr.egress_h.ipv4.isValid())
            if (hdr.ingress_h.inner_ipv4.isValid())
                if (!hdr.ingress_h.gtpu.isValid()) {
                    // gtpu has been decapped. hdr.egress_h.ipv4 should be = to inner_ipv4.
                    hdr.egress_h.ipv4.setValid();
                    hdr.egress_h.ipv4 = hdr.ingress_h.inner_ipv4;
                    hdr.ingress_h.inner_ipv4.setInvalid();
                }

        if (fabric_md.skip_egress){
            exit;
        }

        pkt_io_egress.apply(hdr.egress_h, fabric_md.egress ,standard_md);
        stats.apply(fabric_md.egress.bridged.base.stats_flow_id, standard_md.egress_port,
             fabric_md.egress.bridged.bmd_type);
        egress_next.apply(hdr.egress_h, fabric_md.egress, standard_md);
#ifdef WITH_SPGW
        spgw.apply(hdr.egress_h, fabric_md.egress);
#endif // WITH_SPGW
        dscp_rewriter.apply(fabric_md.egress, standard_md, hdr.egress_h);

        debug.apply();
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
