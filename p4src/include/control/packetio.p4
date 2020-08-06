// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "../header.p4"

control PacketIoIngress(inout parsed_headers_t hdr,
                        inout fabric_ingress_metadata_t fabric_md,
                        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    apply {
        if (hdr.packet_out.isValid()) {
            ig_intr_md_for_tm.ucast_egress_port = hdr.packet_out.egress_port[8:0];
            hdr.packet_out.setInvalid();
            ig_intr_md_for_tm.bypass_egress = 1;
            fabric_md.bridged.setInvalid();
            // No need for ingress processing, straight to egress.
            exit;
        }
    }
}

control PacketIoEgress(inout parsed_headers_t hdr,
                       inout fabric_egress_metadata_t fabric_md,
                       in egress_intrinsic_metadata_t eg_intr_md) {

    apply {
        if (eg_intr_md.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = (bit<16>)fabric_md.bridged.ig_port;
            // No need to process through the rest of the pipeline.
            exit;
        }
    }
}
