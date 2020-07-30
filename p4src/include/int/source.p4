// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

/* -*- P4_16 -*- */
#ifndef __INT_SOURCE__
#define __INT_SOURCE__

// Insert INT header to the packet
control IntSource (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_m) {

    table tb_set_source {
        key = {
            fabric_md.ingress_port: exact @name("ig_port");
        }
        actions = {
            nop;
        }
        const default_action = nop();
        size = MAX_PORTS;
    }

    @hidden
    action int_source(bit<8> max_hop, bit<5> ins_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {
        // Insert INT shim header.
        hdr.intl4_shim.setValid();
        // int_type: Hop-by-hop type (1) , destination type (2)
        hdr.intl4_shim.int_type = 1;
        hdr.intl4_shim.len_words = INT_HEADER_LEN_WORDS;
        // Insert INT header.
        hdr.int_header.setValid();
        hdr.int_header.ver = 0;
        hdr.int_header.rep = 0;
        hdr.int_header.c = 0;
        hdr.int_header.e = 0;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.ins_cnt = ins_cnt;
        hdr.int_header.max_hop_cnt = max_hop;
        hdr.int_header.total_hop_cnt = 0;
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0; // not supported
        hdr.int_header.instruction_mask_1215 = 0; // not supported
        // Insert INT tail header.
        hdr.intl4_tail.setValid();
        hdr.intl4_tail.next_proto = hdr.ipv4.protocol;
        hdr.intl4_tail.dest_port = fabric_md.l4_dport;
        hdr.intl4_tail.dscp = hdr.ipv4.dscp;
        // Update IP and UDP (if not valid we don't care) lens (in bytes).
        hdr.ipv4.total_len = hdr.ipv4.total_len + INT_HEADER_LEN_BYTES;
        hdr.udp.len = hdr.udp.len + INT_HEADER_LEN_BYTES;
    }

    action int_source_dscp(bit<8> max_hop, bit<5> ins_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {
        int_source(max_hop, ins_cnt, ins_mask0003, ins_mask0407);
        hdr.ipv4.dscp = INT_DSCP;
    }

    table tb_int_source {
        key = {
            hdr.ipv4.src_addr: ternary @name("ipv4_src");
            hdr.ipv4.dst_addr: ternary @name("ipv4_dst");
            fabric_md.l4_sport: ternary @name("l4_sport");
            fabric_md.l4_dport: ternary @name("l4_dport");
        }
        actions = {
            int_source_dscp;
            @defaultonly nop();
        }
        const default_action = nop();
    }

    apply {
        if (tb_set_source.apply().hit) {
            tb_int_source.apply();
        }
    }
}
#endif
