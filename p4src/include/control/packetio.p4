// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "../header.p4"

control PacketIoIngress(inout parsed_headers_t hdr,
                        inout fabric_ingress_metadata_t fabric_md,
                        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    @hidden
    action do_packet_out() {
        ig_intr_md_for_tm.ucast_egress_port = hdr.packet_out.egress_port[8:0];
        hdr.packet_out.setInvalid();
        fabric_md.common.setInvalid();
        ig_intr_md_for_tm.bypass_egress = 1;
        // No need for ingress and egress processing, straight to the port.
        exit;
    }

    @hidden
    table tbl_packet_out {
        key = {
            hdr.packet_out.isValid(): exact;
        }
        actions = {
            do_packet_out;
        }
        const size = 1;
        const entries = {
            true: do_packet_out();
        }
    }

    apply {
        tbl_packet_out.apply();
    }
}

control PacketIoEgress(inout parsed_headers_t hdr,
                       inout fabric_egress_metadata_t fabric_md,
                       in egress_intrinsic_metadata_t eg_intr_md) {
    @hidden
    action do_packet_in() {
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (bit<16>)fabric_md.common.ingress_port;
        // No need to process through the rest of the pipeline.
        exit;
    }

    @hidden
    table tbl_packet_in {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            do_packet_in;
        }
        const size = 1;
        const entries = {
            CPU_PORT: do_packet_in();
        }
    }
    apply {
        tbl_packet_in.apply();
    }
}
