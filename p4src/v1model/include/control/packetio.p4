// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "shared/header.p4"

control PacketIoIngress(inout ingress_headers_t hdr,
                        inout fabric_ingress_metadata_t fabric_md,
                        inout bool skip_egress,
                        inout standard_metadata_t standard_md) {
    @hidden
    action do_packet_out() {
        standard_md.egress_spec = hdr.packet_out.egress_port;
        fabric_md.egress_port_set = true;
        hdr.packet_out.setInvalid();
        skip_egress = true;
        // Straight to output port.
        fabric_md.bridged.setInvalid(); 
        exit; // This will start the egress pipeline.
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
        //size = 3;
        const entries = {
            // Regular packet-out.
            CpuLoopbackMode_t.DISABLED: do_packet_out();
            // Pkt should go directly to CPU after port loopback. Not used in Bmv2
            CpuLoopbackMode_t.DIRECT: do_cpu_loopback(ETHERTYPE_CPU_LOOPBACK_EGRESS);
            // Pkt should go through ingress after port loopback. Not used in Bmv2
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
            fabric_md.bridged.setInvalid();
            hdr.fake_ethernet.setInvalid();
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_md.ingress_port;
            exit;
        }
    }
}

control PacketIoEgress(inout ingress_headers_t hdr,
                        inout fabric_egress_metadata_t fabric_md,
                        inout bool skip_egress,
                        inout standard_metadata_t standard_md) {

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

        if (skip_egress){
            exit;
        }

        if (standard_md.egress_port == fabric_md.cpu_port) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_md.ingress_port;
            hdr.fake_ethernet.setInvalid();
            exit;
        }

        // Fix the egress packet length if it is a CPU loopback packet.
        if (hdr.fake_ethernet.isValid() &&
            hdr.fake_ethernet.ether_type == ETHERTYPE_CPU_LOOPBACK_EGRESS) {
                fabric_md.pkt_length = (bit<16>)standard_md.packet_length - ETH_HDR_BYTES;
        }
    }
}
