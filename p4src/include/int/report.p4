// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

/* -*- P4_16 -*- */
#ifndef __INT_REPORT__
#define __INT_REPORT__

control IntReport (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md) {

    Random<bit<16>>() ip_id_gen;

    @hidden
    action add_report_fixed_header() {
        /* Device should include its own INT metadata as embedded,
         * we'll not use fabric_report_header for this purpose.
         */
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 0;
        /* only support for flow_watchlist */
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        hdr.report_fixed_header.d = 0;
        hdr.report_fixed_header.q = 0;
        hdr.report_fixed_header.f = 1;
        hdr.report_fixed_header.rsvd = 0;
        //TODO how to get information specific to the switch
        hdr.report_fixed_header.hw_id = HW_ID;
        // TODO how save a variable and increment
        hdr.report_fixed_header.seq_no = 0;
        hdr.report_fixed_header.ingress_tstamp = fabric_md.int_ingress_tstamp;
        // Local report
        hdr.local_report_header.setValid();
        hdr.local_report_header.switch_id = fabric_md.int_switch_id;
        hdr.local_report_header.ingress_port_id = fabric_md.int_ingress_port_id;
        hdr.local_report_header.egress_port_id = fabric_md.int_egress_port_id;
        hdr.local_report_header.queue_id = fabric_md.int_q_id;
        hdr.local_report_header.queue_occupancy = fabric_md.int_q_occupancy;
        hdr.local_report_header.egress_tstamp = fabric_md.int_egress_tstamp;
    }

    action do_report_encapsulation(mac_addr_t src_mac, mac_addr_t mon_mac,
                                   ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                   l4_port_t mon_port) {
        //Report Ethernet Header
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dst_addr = mon_mac;
        hdr.report_ethernet.src_addr = src_mac;
        hdr.report_eth_type.setValid();
        hdr.report_eth_type.value = ETHERTYPE_IPV4;

        //Report IPV4 Header
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4w4;
        hdr.report_ipv4.ihl = 4w5;
        hdr.report_ipv4.dscp = 6w0;
        hdr.report_ipv4.ecn = 2w0;
        // IPv4 Total length is length of
        // IPv4(20) + UDP(8) + Fixed report header(12) + Local report(16) + Original packet
        // The original packet length should be the one from egress intrinsic metadata minus
        // the length of mirror data (21 bytes) and CRC (4 bytes).
        hdr.report_ipv4.total_len = IPV4_MIN_HEAD_LEN + UDP_HEADER_LEN
                                    + REPORT_FIXED_HEADER_LEN + LOCAL_REPORT_HEADER_LEN
                                    - REPORT_MIRROR_HEADER_LEN
                                    - CRC_CHECKSUM_LEN
                                    + eg_intr_md.pkt_length ;
        /* Dont Fragment bit should be set */
        hdr.report_ipv4.identification = ip_id_gen.get();
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = 64;
        hdr.report_ipv4.protocol = PROTO_UDP;
        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;

        //Report UDP Header
        hdr.report_udp.setValid();
        hdr.report_udp.sport = 0;
        hdr.report_udp.dport = mon_port;
        // See IPv4 length
        hdr.report_udp.len = UDP_HEADER_LEN + REPORT_FIXED_HEADER_LEN
                             + LOCAL_REPORT_HEADER_LEN
                             - REPORT_MIRROR_HEADER_LEN
                             - CRC_CHECKSUM_LEN
                             + eg_intr_md.pkt_length ;
        add_report_fixed_header();
    }

    table tb_generate_report {
        key = {
            fabric_md.mirror_session_id: exact;
        }
        actions = {
            do_report_encapsulation;
            @defaultonly nop();
        }
        const default_action = nop;
        size = 4;
    }

    @hidden
    action fix_dscp_bit() {
        hdr.ipv4.dscp = INT_DSCP;
    }

    @hidden
    table fix_dscp {
        key = {
            fabric_md.ingress_port: exact;
        }
        actions = {
            fix_dscp_bit;
        }
        const entries = {
            0x44: fix_dscp_bit;
            0xC4: fix_dscp_bit;
            0x144: fix_dscp_bit;
            0x1C4: fix_dscp_bit;
        }
        size = 4;
    }

    apply {
        tb_generate_report.apply();
        fix_dscp.apply();
    }
}
#endif
