// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "../header.p4"

control PacketIoIngress(inout parsed_headers_t hdr,
                        inout fabric_ingress_metadata_t fabric_md,
                        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
                        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
    @hidden
    action do_packet_out() {
        ig_intr_md_for_tm.ucast_egress_port = hdr.packet_out.egress_port;
        hdr.packet_out.setInvalid();
        // Straight to output port.
        fabric_md.bridged.setInvalid();
        ig_intr_md_for_tm.bypass_egress = 1;
        exit;
    }

    @hidden
    action do_cpu_loopback(bit<16> fake_ether_type) {
        hdr.fake_ethernet.setValid();
        hdr.fake_ethernet.ether_type = fake_ether_type;
        do_packet_out();
    }

    @hidden
    table packet_out_modes {
        key = {
            hdr.packet_out.cpu_loopback_mode: exact;
        }
        actions = {
            do_packet_out;
            do_cpu_loopback;
            @defaultonly nop;
        }
        const default_action = nop();
        size = 3;
        const entries = {
            // Regular packet-out.
            CpuLoopbackMode_t.DISABLED: do_packet_out();
            // Pkt should go directly to CPU after port loopback.
            CpuLoopbackMode_t.DIRECT: do_cpu_loopback(ETHERTYPE_CPU_LOOPBACK_EGRESS);
            // Pkt should go through ingress after port loopback.
            CpuLoopbackMode_t.INGRESS: do_cpu_loopback(ETHERTYPE_CPU_LOOPBACK_INGRESS);
        }
    }

    apply {
        if (hdr.packet_out.isValid()) {
            packet_out_modes.apply();
        } else if (hdr.fake_ethernet.isValid() &&
                       hdr.fake_ethernet.ether_type == ETHERTYPE_CPU_LOOPBACK_EGRESS) {
            // CPU loopback pkt entering the ingress pipe a second time (after
            // going through egress). Punt to CPU now.
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

    action set_cpu_port(PortId_t cpu_port) {
        fabric_md.cpu_port = cpu_port;
    }

    table switch_info {
        actions = {
            set_cpu_port;
            @defaultonly nop;
        }
        default_action = nop;
    }

    apply {
        switch_info.apply();
        // Check if this is a clone of a copy_to_cpu packet.
        if (eg_intr_md.egress_port == fabric_md.cpu_port) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = fabric_md.bridged.ig_port;
            hdr.fake_ethernet.setInvalid();
            // Straight to CPU. No need to process through the rest of the
            // egress pipe.
            exit;
        }
    }
}
