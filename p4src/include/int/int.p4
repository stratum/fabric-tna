// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __INT_MAIN__
#define __INT_MAIN__

#include "define.p4"
#include "header.p4"


control FlowReportFilter(
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md) {

    Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_state_hasher;
    bit<16> flow_state_hash;
    bit<32> hop_latency;
    bit<1> report;

    // Bloom filter storing the hashed state of each flow (ports and hop latency).
    // We use it to trigger report generation only for the first packet of a new flow, or for
    // packets which state has changed with respect to the previous packet of the same flow.
    @switchstack("register_reset_interval_ms: 1000")
    @switchstack("register_reset_value: 0")
    Register<flow_report_filter_index_t, bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH, 0) filter1;
    @switchstack("register_reset_interval_ms: 1000")
    @switchstack("register_reset_value: 0")
    Register<flow_report_filter_index_t, bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH, 0) filter2;

    // Meaning of the result:
    // 0: Nothing changed.
    // 1: New flow or state hash changed.
    RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter1) filter_get_and_set1 = {
        void apply(inout bit<16> stored_flow_state_hash, out bit<1> result) {
            if (stored_flow_state_hash == 0) {
                // No state hash stored, new flow.
                result = 1;
            } else if (stored_flow_state_hash != flow_state_hash) {
                // State hash changed.
                result = 1;
            } else {
                // Nothing changed.
                result = 0;
            }
            stored_flow_state_hash = flow_state_hash;
        }
    };

    RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter2) filter_get_and_set2 = {
        void apply(inout bit<16> stored_flow_state_hash, out bit<1> result) {
            if (stored_flow_state_hash == 0) {
                // No state hash stored, new flow.
                result = 1;
            } else if (stored_flow_state_hash != flow_state_hash) {
                // State hash changed.
                result = 1;
            } else {
                // Nothing changed.
                result = 0;
            }
            stored_flow_state_hash = flow_state_hash;
        }
    };

    action quantize(bit<32> qmask) {
        hop_latency = hop_latency & qmask;
    }

    table quantize_hop_latency {
        key = {}
        actions = {
            @defaultonly quantize;
        }
        default_action = quantize(0xffffffff);
    }

    apply {
        hop_latency = eg_prsr_md.global_tstamp[31:0] - fabric_md.bridged.ig_tstamp[31:0];
        quantize_hop_latency.apply();
        flow_state_hash = flow_state_hasher.get({fabric_md.bridged.ig_port, eg_intr_md.egress_port, hop_latency});
        report = filter_get_and_set1.execute(fabric_md.bridged.flow_hash[31:16]);
        report = report | filter_get_and_set2.execute(fabric_md.bridged.flow_hash[15:0]);
        if (report == 0) {
            fabric_md.int_mirror_md.setInvalid();
        }
    }
}

control IntEgress (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md) {

    FlowReportFilter() flow_report_filter;

    @hidden
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
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 0;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        hdr.report_fixed_header.d = 0;
        hdr.report_fixed_header.q = 0;
        hdr.report_fixed_header.f = 1;
        hdr.report_fixed_header.rsvd = 0;
        hdr.report_fixed_header.ig_tstamp = fabric_md.int_mirror_md.ig_tstamp;

        hdr.local_report_header.setValid();
        hdr.local_report_header.switch_id = fabric_md.int_mirror_md.switch_id;
        hdr.local_report_header.ig_port = fabric_md.int_mirror_md.ig_port;
        hdr.local_report_header.eg_port = fabric_md.int_mirror_md.eg_port;
        hdr.local_report_header.queue_id = fabric_md.int_mirror_md.queue_id;
        hdr.local_report_header.queue_occupancy = fabric_md.int_mirror_md.queue_occupancy;
        hdr.local_report_header.eg_tstamp = fabric_md.int_mirror_md.eg_tstamp;
    }

    action do_report_encap(mac_addr_t src_mac, mac_addr_t mon_mac,
                           ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                           l4_port_t mon_port) {
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dst_addr = mon_mac;
        hdr.report_ethernet.src_addr = src_mac;
        hdr.report_eth_type.setValid();
        hdr.report_eth_type.value = ETHERTYPE_IPV4;

        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4w4;
        hdr.report_ipv4.ihl = 4w5;
        hdr.report_ipv4.dscp = INT_DSCP;
        hdr.report_ipv4.ecn = 2w0;
        hdr.report_ipv4.total_len = IPV4_HDR_SIZE + UDP_HDR_SIZE
                                    + REPORT_FIXED_HEADER_LEN + LOCAL_REPORT_HEADER_LEN
                                    - REPORT_MIRROR_HEADER_LEN
                                    - ETH_FCS_LEN
                                    + eg_intr_md.pkt_length;
        hdr.report_ipv4.identification = ip_id_gen.get();
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.report_ipv4.protocol = PROTO_UDP;
        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;

        hdr.report_udp.setValid();
        hdr.report_udp.sport = 0;
        hdr.report_udp.dport = mon_port;
        hdr.report_udp.len = UDP_HDR_SIZE + REPORT_FIXED_HEADER_LEN
                             + LOCAL_REPORT_HEADER_LEN
                             - REPORT_MIRROR_HEADER_LEN
                             - ETH_FCS_LEN
                             + eg_intr_md.pkt_length;
        add_report_fixed_header();
    }

    action do_report_encap_mpls(mac_addr_t src_mac, mac_addr_t mon_mac,
                                ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                l4_port_t mon_port, mpls_label_t mon_label) {
        do_report_encap(src_mac, mon_mac, src_ip, mon_ip, mon_port);
        hdr.report_eth_type.value = ETHERTYPE_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.label = mon_label;
        hdr.report_mpls.tc = 0;
        hdr.report_mpls.bos = 1;
        hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;
    }

    table report {
        key = {
            fabric_md.int_mirror_md.isValid(): exact @name("int_mirror_valid");
        }
        actions = {
            do_report_encap;
            do_report_encap_mpls;
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

    action init_metadata(bit<32> switch_id) {
        fabric_md.int_mirror_md.setValid();
        fabric_md.int_mirror_md.bridged_md_type = BridgedMdType_t.INT_MIRROR;
        fabric_md.int_mirror_md.switch_id = switch_id;
        fabric_md.int_mirror_md.ig_port = (bit<16>)fabric_md.bridged.ig_port;
        fabric_md.int_mirror_md.eg_port = (bit<16>)eg_intr_md.egress_port;
        fabric_md.int_mirror_md.queue_id = (bit<8>)eg_intr_md.egress_qid;
        fabric_md.int_mirror_md.queue_occupancy = (bit<24>)eg_intr_md.enq_qdepth;
        fabric_md.int_mirror_md.ig_tstamp = fabric_md.bridged.ig_tstamp[31:0];
        fabric_md.int_mirror_md.eg_tstamp = eg_prsr_md.global_tstamp[31:0];
#ifdef WITH_SPGW
        fabric_md.int_mirror_md.strip_gtpu = fabric_md.int_strip_gtpu;
#endif // WITH_SPGW
    }

    table watchlist {
        key = {
            hdr.ipv4.src_addr          : ternary @name("ipv4_src");
            hdr.ipv4.dst_addr          : ternary @name("ipv4_dst");
            fabric_md.bridged.ip_proto : ternary @name("ip_proto");
            fabric_md.bridged.l4_sport : range @name("l4_sport");
            fabric_md.bridged.l4_dport : range @name("l4_dport");
        }
        actions = {
            init_metadata;
            @defaultonly nop();
        }
        const default_action = nop();
        const size = WATCHLIST_TABLE_SIZE;
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
            PIPE_0_PORTS_MATCH: set_mirror_session_id(REPORT_MIRROR_SESS_PIPE_0);
            PIPE_1_PORTS_MATCH: set_mirror_session_id(REPORT_MIRROR_SESS_PIPE_1);
            PIPE_2_PORTS_MATCH: set_mirror_session_id(REPORT_MIRROR_SESS_PIPE_2);
            PIPE_3_PORTS_MATCH: set_mirror_session_id(REPORT_MIRROR_SESS_PIPE_3);
        }
    }

    apply {
        if (report.apply().hit) {
            report_seq_no_and_hw_id.apply();
            // Remove the INT mirror metadata to prevent egress mirroring again.
            fabric_md.int_mirror_md.setInvalid();
#ifdef WITH_SPGW
            if (fabric_md.int_mirror_md.strip_gtpu == 1) {
                // We need to remove length of IP, UDP, and GTPU headers
                // since we only monitor the packet inside the GTP tunnel.
                hdr.report_ipv4.total_len = hdr.report_ipv4.total_len
                    - (IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_SIZE);
                hdr.report_udp.len = hdr.report_udp.len
                    - (IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_SIZE);
            }
#endif // WITH_SPGW
            if (fabric_md.int_strip_mpls == 1) {
                // We need to remove length of MPLS since we don't include MPLS
                // header in INT report.
                hdr.report_ipv4.total_len = hdr.report_ipv4.total_len
                    - MPLS_HDR_SIZE;
                hdr.report_udp.len = hdr.report_udp.len
                    - MPLS_HDR_SIZE;
            }
            // Reports don't need to go through the rest of the egress pipe.
            exit;
        } else {
            mirror_session_id.apply();
            if (hdr.ipv4.isValid()) {
                if (watchlist.apply().hit) {
                    flow_report_filter.apply(hdr, fabric_md, eg_intr_md, eg_prsr_md);
                }
            }
        }
    }
}
#endif
