// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "../header.p4"

control PacketIoIngress(inout parsed_headers_t hdr,
                        inout fabric_ingress_metadata_t fabric_md,
                        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
                        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    apply {
        if (hdr.packet_out.isValid()) {
            ig_intr_md_for_tm.ucast_egress_port = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            fabric_md.bridged.setInvalid();
            ig_intr_md_for_tm.bypass_egress = 1;
            if (hdr.packet_out.cpu_loopback == 1w1) {
                hdr.fake_ethernet.setValid();
                hdr.fake_ethernet.ether_type = ETHERTYPE_CPU_LOOPBACK_INGRESS;
            }
            // No need for ingress processing, straight to egress.
            exit;
        } else if (hdr.fake_ethernet.isValid() &&
                hdr.fake_ethernet.ether_type == ETHERTYPE_CPU_LOOPBACK_EGRESS) {
            // This is a CPU loopback packet that has been processed by the
            // egress pipe, and i has entered the ingress pipe a second time.
            // Punt to CPU now.
            hdr.fake_ethernet.setInvalid();
            ig_intr_md_for_tm.copy_to_cpu = 1;
            ig_intr_md_for_dprsr.drop_ctl = 1;
            exit;
        }
    }
}

control PacketIoEgress(inout parsed_headers_t hdr,
                       inout fabric_egress_metadata_t fabric_md,
                       in egress_intrinsic_metadata_t eg_intr_md) {

    apply {
        if (hdr.fake_ethernet.isValid() &&
                hdr.fake_ethernet.ether_type == ETHERTYPE_CPU_LOOPBACK_INGRESS) {
            hdr.fake_ethernet.ether_type = ETHERTYPE_CPU_LOOPBACK_EGRESS;
        }

        if (eg_intr_md.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = fabric_md.bridged.ig_port;
            // No need to process through the rest of the pipeline.
            exit;
        }
    }
}
