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

    action restore_header_len_field() {
        bytes_removed = field_size_modifier.get<bit<10>>(hdr.intl4_shim.len_words ++ 2w0);
        hdr.ipv4.total_len = hdr.ipv4.total_len - bytes_removed;
        hdr.udp.len = hdr.udp.len - bytes_removed;
    }

    table tbl_restore_header_len_field {
        key = {
            hdr.intl4_shim.isValid(): exact;
        }
        actions = {
            restore_header_len_field;
            @defaultonly nop;
        }
        default_action = nop;
        const entries = {
            true: restore_header_len_field;
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

    apply {
        if (!tb_set_sink.apply().hit) {
            return;
        }
        tbl_restore_header_len_field.apply();

        hdr.udp.dport = hdr.intl4_tail.dest_port;
        hdr.ipv4.dscp = hdr.intl4_tail.dscp;

        fabric_md.int_len_words = hdr.intl4_shim.len_words;
        fabric_md.int_switch_id = hdr.int_switch_id.switch_id;
        fabric_md.int_ingress_port_id = hdr.int_port_ids.ingress_port_id;
        fabric_md.int_egress_port_id = hdr.int_port_ids.egress_port_id;
        fabric_md.int_hop_latency = hdr.int_hop_latency.hop_latency;

        // remove all the INT information from the packet
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

        // TODO: include all INT data from previous nodes
        // hdr.int_data[0].setInvalid();
        // hdr.int_data[1].setInvalid();
        // hdr.int_data[2].setInvalid();
        // hdr.int_data[3].setInvalid();
        // hdr.int_data[4].setInvalid();
        // hdr.int_data[5].setInvalid();
        // hdr.int_data[6].setInvalid();
        // hdr.int_data[7].setInvalid();
        // hdr.int_data[8].setInvalid();
        // hdr.int_data[9].setInvalid();
        // hdr.int_data[10].setInvalid();
        // hdr.int_data[11].setInvalid();
        // hdr.int_data[12].setInvalid();
        // hdr.int_data[13].setInvalid();
        // hdr.int_data[14].setInvalid();
        // hdr.int_data[15].setInvalid();
        // hdr.int_data[16].setInvalid();
        // hdr.int_data[17].setInvalid();
        // hdr.int_data[18].setInvalid();
        // hdr.int_data[19].setInvalid();
        // hdr.int_data[20].setInvalid();
        // hdr.int_data[21].setInvalid();
        // hdr.int_data[22].setInvalid();
        // hdr.int_data[23].setInvalid();
        // fabric_md.bridge_md_type = BridgeMetadataType.BRIDGE_MD_MIRROR_EGRESS_TO_EGRESS;
    }
}
#endif
