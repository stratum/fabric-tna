// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

/* -*- P4_16 -*- */
#ifndef __INT_MAIN__
#define __INT_MAIN__

#include "define.p4"
#include "header.p4"

control IntEgress (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md) {

    Random<bit<16>>() ip_id_gen;
    @hidden
    Register<bit<32>, bit<6>>(1024) seq_number;
    RegisterAction<bit<32>, bit<6>, bit<32>>(seq_number) get_seq_number = {
        void apply(inout bit<32> reg, out bit<32> rv) {
            reg = reg + 1;
            rv = reg;
        }
    };

    @hidden
    action add_report_fixed_header() {
        /* Device should include its own INT metadata as embedded,
         * we'll not use fabric_report_header for this purpose.
         */
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 0;
        /* only support for int_collectorlist */
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        hdr.report_fixed_header.d = 0;
        hdr.report_fixed_header.q = 0;
        hdr.report_fixed_header.f = 1;
        hdr.report_fixed_header.rsvd = 0;
        hdr.report_fixed_header.ingress_tstamp = fabric_md.int_mirror_md.ig_tstamp;
        // Local report
        hdr.local_report_header.setValid();
        hdr.local_report_header.switch_id = fabric_md.int_mirror_md.switch_id;
        hdr.local_report_header.ingress_port_id = fabric_md.int_mirror_md.ig_port;
        hdr.local_report_header.egress_port_id = fabric_md.int_mirror_md.eg_port;
        hdr.local_report_header.queue_id = fabric_md.int_mirror_md.queue_id;
        hdr.local_report_header.queue_occupancy = fabric_md.int_mirror_md.queue_occupancy;
        hdr.local_report_header.egress_tstamp = fabric_md.int_mirror_md.eg_tstamp;
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
        hdr.report_ipv4.dscp = INT_DSCP;
        hdr.report_ipv4.ecn = 2w0;
        // IPv4 Total length is length of
        // IPv4(20) + UDP(8) + Fixed report header(12) + Local report(16) + Original packet
        // The original packet length should be the one from egress intrinsic metadata minus
        // the length of mirror data (23/24 bytes) and CRC (4 bytes).
        hdr.report_ipv4.total_len = IPV4_HDR_SIZE + UDP_HDR_SIZE
                                    + REPORT_FIXED_HEADER_LEN + LOCAL_REPORT_HEADER_LEN
                                    - REPORT_MIRROR_HEADER_LEN
                                    - CRC_CHECKSUM_LEN
                                    + eg_intr_md.pkt_length;
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
        hdr.report_udp.len = UDP_HDR_SIZE + REPORT_FIXED_HEADER_LEN
                             + LOCAL_REPORT_HEADER_LEN
                             - REPORT_MIRROR_HEADER_LEN
                             - CRC_CHECKSUM_LEN
                             + eg_intr_md.pkt_length;
        add_report_fixed_header();
    }

    table report {
        key = {
            fabric_md.int_mirror_md.isValid(): exact @name("int_mirror_valid");
        }
        actions = {
            do_report_encapsulation;
            @defaultonly nop();
        }
        default_action = nop;
        const size = 1;
    }

    @hidden
    action set_report_seq_no_and_hw_id(bit<6> hw_id) {
        hdr.report_fixed_header.hw_id = hw_id;
        hdr.report_fixed_header.seq_no = get_seq_number.execute(hw_id);
    }

    @hidden
    table report_seq_no_and_hw_id {
        key = {
            eg_intr_md.egress_port: ternary;
        }
        actions = {
            set_report_seq_no_and_hw_id;
        }
        const size = 4;
        const entries = {
            PIPE_0_PORTS_MATCH: set_report_seq_no_and_hw_id(0);
            PIPE_1_PORTS_MATCH: set_report_seq_no_and_hw_id(1);
            PIPE_2_PORTS_MATCH: set_report_seq_no_and_hw_id(2);
            PIPE_3_PORTS_MATCH: set_report_seq_no_and_hw_id(3);
        }
    }

    action collect(bit<32> switch_id) {
        fabric_md.int_mirror_md.setValid();
        fabric_md.int_mirror_md.bridge_md_type = BridgedMetadataType_t.MIRROR_EGRESS_TO_EGRESS;
        fabric_md.int_mirror_md.switch_id = switch_id;
        fabric_md.int_mirror_md.ig_port = (bit<16>)fabric_md.bridged.ig_port;
        fabric_md.int_mirror_md.eg_port = (bit<16>)eg_intr_md.egress_port;
        fabric_md.int_mirror_md.queue_id = (bit<8>)eg_intr_md.egress_qid;
        fabric_md.int_mirror_md.queue_occupancy = (bit<24>)eg_intr_md.enq_qdepth;
        fabric_md.int_mirror_md.ig_tstamp = fabric_md.bridged.ig_tstamp[31:0];
        fabric_md.int_mirror_md.eg_tstamp = eg_prsr_md.global_tstamp[31:0];
#ifdef WITH_SPGW
        // We will set this later in spgw egress pipeline.
        fabric_md.int_mirror_md.skip_gtpu_headers = 0;
#endif
    }

    table collector {
        key = {
            hdr.ipv4.src_addr: ternary @name("ipv4_src");
            hdr.ipv4.dst_addr: ternary @name("ipv4_dst");
            fabric_md.bridged.l4_sport: range @name("l4_sport");
            fabric_md.bridged.l4_dport: range @name("l4_dport");
        }
        actions = {
            collect;
            @defaultonly nop();
        }
        const default_action = nop();
        const size = COLLECTOR_TABLE_SIZE;
    }

    @hidden
    action set_mirror_session_id(MirrorId_t sid) {
        fabric_md.int_mirror_md.mirror_session_id = sid;
    }

    @hidden
    table mirror_session_id {
        key = {
            fabric_md.bridged.ig_port: ternary;
        }
        actions = {
            set_mirror_session_id;
        }
        size = 4;
        const entries = {
            PIPE_0_PORTS_MATCH: set_mirror_session_id(300);
            PIPE_1_PORTS_MATCH: set_mirror_session_id(301);
            PIPE_2_PORTS_MATCH: set_mirror_session_id(302);
            PIPE_3_PORTS_MATCH: set_mirror_session_id(303);
        }
    }

    apply {
        if (report.apply().hit) {
            report_seq_no_and_hw_id.apply();
            // Remove the INT mirror metadata to prevent
            // infinity loop
            fabric_md.int_mirror_md.setInvalid();

#ifdef WITH_SPGW
            if (fabric_md.int_mirror_md.skip_gtpu_headers == 1) {
                // Need to remove length of IP, UDP, and GTPU headers (36 bytes)
                // if we encapsulate the packet with GTPU.
                hdr.report_ipv4.total_len = hdr.report_ipv4.total_len - (IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_SIZE);
                hdr.report_udp.len = hdr.report_udp.len - (IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_SIZE);
            }
#endif // WITH_SPGW
        } else {
            if (fabric_md.bridged.ig_port != CPU_PORT &&
                eg_intr_md.egress_port != CPU_PORT) {
                if (collector.apply().hit) {
                    mirror_session_id.apply();
                }
            }
        }
    }
}
#endif
