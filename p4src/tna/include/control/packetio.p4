// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "shared/header.p4"

control PacketIoIngress(inout ingress_headers_t hdr,
                        inout fabric_ingress_metadata_t fabric_md,
                        in    ingress_intrinsic_metadata_t ig_intr_md,
                        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
                        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
    @hidden
    action do_packet_out() {
        ig_intr_md_for_tm.ucast_egress_port = (PortId_t)hdr.packet_out.egress_port;
        ig_intr_md_for_tm.qid = hdr.packet_out.queue_id;
        fabric_md.egress_port_set = true;
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
            // going through egress). Punt to CPU now, skip egress.
            ig_intr_md_for_tm.copy_to_cpu = 1;
            ig_intr_md_for_dprsr.drop_ctl = 1;
            ig_intr_md_for_tm.bypass_egress = 1;
            fabric_md.bridged.setInvalid();
            hdr.fake_ethernet.setInvalid();
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = (FabricPortId_t)ig_intr_md.ingress_port;
            exit;
        }
    }
}

control PacketIoEgress(inout egress_headers_t hdr,
                       inout fabric_egress_metadata_t fabric_md,
                       in egress_intrinsic_metadata_t eg_intr_md) {

    // TODO(Yi Tseng): Currently, we don't translate the CPU port, but maybe we
    // can use a fixed number for CPU port in the chassis config.
    action set_switch_info(PortId_t cpu_port) {
        fabric_md.cpu_port = cpu_port;
    }

    table switch_info {
        actions = {
            set_switch_info;
            @defaultonly nop;
        }
        default_action = nop;
        const size = 1;
    }

    apply {
        switch_info.apply();
        if (eg_intr_md.egress_port == fabric_md.cpu_port) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = (FabricPortId_t)fabric_md.bridged.base.ig_port;
            hdr.fake_ethernet.setInvalid();
            // Straight to CPU. No need to process through the rest of the
            // egress pipe.
            exit;
        }
        // Fix the egress packet length if it is a CPU loopback packet.
        if (hdr.fake_ethernet.isValid() &&
            hdr.fake_ethernet.ether_type == ETHERTYPE_CPU_LOOPBACK_EGRESS) {
                fabric_md.pkt_length = eg_intr_md.pkt_length - ETH_HDR_BYTES;
        }
    }
}
