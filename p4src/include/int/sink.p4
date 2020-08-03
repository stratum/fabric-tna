// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

/* -*- P4_16 -*- */
#ifndef __INT_SINK__
#define __INT_SINK__

control IntSink (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md) {

    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) field_size_modifier;
    bit<16> bytes_removed;

    @hidden
    action calculate_removed_bytes() {
        bytes_removed = field_size_modifier.get<bit<10>>(hdr.intl4_shim.len_words ++ 2w0);
    }

    @hidden
    table tbl_calculate_removed_bytes {
        key = {
            hdr.intl4_shim.isValid(): exact;
        }
        actions = {
            calculate_removed_bytes;
            @defaultonly nop;
        }
        default_action = nop;
        const entries = {
            true: calculate_removed_bytes;
        }
        size = 1;
    }

    table tb_set_sink {
        key = {
            eg_intr_md.egress_port: exact @name("eg_port");
        }
        actions = {
            nop;
        }
        const default_action = nop();
        size = MAX_PORTS;
    }


    action set_mirror_session_id(MirrorId_t sid) {
        fabric_md.mirror_session_id = sid;
    }

    table tb_set_mirror_session_id {
        key = {
            fabric_md.ingress_port: ternary;
        }
        actions = {
            set_mirror_session_id;
        }
        size = 4;
        const entries = {
            9w0x000 &&& 0x180: set_mirror_session_id(300);
            9w0x080 &&& 0x180: set_mirror_session_id(301);
            9w0x100 &&& 0x180: set_mirror_session_id(302);
            9w0x180 &&& 0x180: set_mirror_session_id(303);
        }
    }

    apply {
        if (!tb_set_sink.apply().hit) {
            return;
        }
        bytes_removed = 0;
        tbl_calculate_removed_bytes.apply();

        hdr.ipv4.total_len = hdr.ipv4.total_len - bytes_removed;
        hdr.udp.len = hdr.udp.len - bytes_removed;
        hdr.udp.dport = hdr.intl4_tail.dest_port;
        hdr.ipv4.dscp = hdr.intl4_tail.dscp;

        fabric_md.int_switch_id = hdr.int_switch_id.switch_id;
        fabric_md.int_ingress_port_id = hdr.int_port_ids.ingress_port_id;
        fabric_md.int_egress_port_id = hdr.int_port_ids.egress_port_id;
        fabric_md.int_q_id = hdr.int_q_occupancy.q_id;
        fabric_md.int_q_occupancy = hdr.int_q_occupancy.q_occupancy;
        fabric_md.int_ingress_tstamp = hdr.int_ingress_tstamp.ingress_tstamp;
        fabric_md.int_egress_tstamp = hdr.int_egress_tstamp.egress_tstamp;

        hdr.int_header.setInvalid();
        hdr.intl4_shim.setInvalid();
        hdr.intl4_tail.setInvalid();
        hdr.int_switch_id.setInvalid();
        hdr.int_port_ids.setInvalid();
        hdr.int_hop_latency.setInvalid();
        hdr.int_q_occupancy.setInvalid();
        hdr.int_ingress_tstamp.setInvalid();
        hdr.int_egress_tstamp.setInvalid();
        hdr.int_q_congestion.setInvalid();
        hdr.int_egress_tx_util.setInvalid();

        fabric_md.bridge_md_type = BridgeMetadataType.MIRROR_EGRESS_TO_EGRESS;
        tb_set_mirror_session_id.apply();
    }
}
#endif
