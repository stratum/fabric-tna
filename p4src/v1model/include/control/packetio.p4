// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "v1model/include/header_v1model.p4"

control PacketIoIngress(inout ingress_headers_t         hdr,
                        inout fabric_ingress_metadata_t fabric_md,
                        inout bool                      skip_egress,
                        inout standard_metadata_t       standard_md,
                        inout FabricPortId_t            recirc_preserved_egress_port) {
    @hidden
    action do_packet_out() {
        standard_md.egress_spec = (PortId_t)hdr.packet_out.egress_port;
        recirc_preserved_egress_port = hdr.packet_out.egress_port;
        fabric_md.egress_port_set = true;
        hdr.packet_out.setInvalid();
        skip_egress = true;
        // Straight to output port.
        fabric_md.bridged.setInvalid();
        exit; // This will start the egress pipeline.
    }

    apply {
        if (hdr.packet_out.isValid()) {
            do_packet_out();
        }
    }
}

control PacketIoEgress(inout ingress_headers_t        hdr,
                       inout fabric_egress_metadata_t fabric_md,
                       inout standard_metadata_t      standard_md,
                       in    FabricPortId_t           preserved_ig_port) {

    action set_switch_info(FabricPortId_t cpu_port) {
        fabric_md.cpu_port = (PortId_t)cpu_port;
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
        if (standard_md.egress_port == fabric_md.cpu_port) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = preserved_ig_port;
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
