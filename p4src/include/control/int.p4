// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_MAIN__
#define __INT_MAIN__

#include "../define.p4"
#include "../header.p4"

control FlowReportFilter(
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    // By default report every 2^30 ns (~1 second)
    const bit<48> DEFAULT_TIMESTAMP_MASK = 0xffffc0000000;
    // or for hop latency changes greater than 2^8 ns
    const bit<32> DEFAULT_HOP_LATENCY_MASK = 0xffffff00;

    Hash<bit<16>>(HashAlgorithm_t.CRC16) digester;
    bit<16> digest;
    bit<32> hop_latency;
    bit<48> timestamp;
    bit<1> flag;

    // Bloom filter with 2 hash functions storing flow digests. The digest is
    // the hash of:
    // - flow state (ingress port, egress port, quantized hop latency);
    // - quantized timestamp (to generate periodic reports).
    // - 5-tuple hash (to detect collisions);
    // We use such filter to reduce the volume of reports that the collector has
    // to ingest. We generate a report only when we detect a change, that is,
    // when the digest of the packet is different than the one of the previous
    // packet of the same flow.
    @hidden
    Register<flow_report_filter_index_t, bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH, 0) filter1;
    @hidden
    Register<flow_report_filter_index_t, bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH, 0) filter2;

    // Meaning of the result:
    // 1 digest did NOT change
    // 0 change detected
    @reduction_or_group("filter")
    RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter1) filter_get_and_set1 = {
        void apply(inout bit<16> stored_digest, out bit<1> result) {
            result = stored_digest == digest ? 1w1 : 1w0;
            stored_digest = digest;
        }
    };

    @reduction_or_group("filter")
    RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter2) filter_get_and_set2 = {
        void apply(inout bit<16> stored_digest, out bit<1> result) {
            result = stored_digest == digest ? 1w1 : 1w0;
            stored_digest = digest;
        }
    };

    action set_config(bit<32> hop_latency_mask, bit<48> timestamp_mask) {
        hop_latency = hop_latency & hop_latency_mask;
        timestamp = timestamp & timestamp_mask;
    }

    table config {
        actions = {
            @defaultonly set_config;
        }
        default_action = set_config(DEFAULT_HOP_LATENCY_MASK, DEFAULT_TIMESTAMP_MASK);
    }

    apply {
        hop_latency = eg_prsr_md.global_tstamp[31:0] - fabric_md.bridged.ig_tstamp[31:0];
        timestamp = fabric_md.bridged.ig_tstamp;
        config.apply();
        digest = digester.get({ // burp!
            fabric_md.bridged.ig_port,
            eg_intr_md.egress_port,
            hop_latency,
            fabric_md.bridged.flow_hash,
            timestamp
        });
        flag = filter_get_and_set1.execute(fabric_md.bridged.flow_hash[31:16]);
        flag = flag | filter_get_and_set2.execute(fabric_md.bridged.flow_hash[15:0]);
        // Generate report only when ALL register actions detect a change.
        if (flag == 1) {
            eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
        }
    }
}


control DropReportFilter(
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    Hash<bit<16>>(HashAlgorithm_t.CRC16) digester;
    bit<16> digest;
    bit<1> flag;

    // Bloom filter with 2 hash functions storing flow digests. The digest is
    // the hash of:
    // - quantized timestamp (to generate periodic reports).
    // - 5-tuple hash (to detect collisions);
    // We use such filter to reduce the volume of reports that the collector has
    // to ingest.
    @hidden
    Register<drop_report_filter_index_t, bit<16>>(1 << DROP_REPORT_FILTER_WIDTH, 0) filter1;
    @hidden
    Register<drop_report_filter_index_t, bit<16>>(1 << DROP_REPORT_FILTER_WIDTH, 0) filter2;

    // Meaning of the result:
    // 1 digest did NOT change
    // 0 change detected
    @reduction_or_group("filter")
    RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter1) filter_get_and_set1 = {
        void apply(inout bit<16> stored_digest, out bit<1> result) {
            result = stored_digest == digest ? 1w1 : 1w0;
            stored_digest = digest;
        }
    };

    @reduction_or_group("filter")
    RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter2) filter_get_and_set2 = {
        void apply(inout bit<16> stored_digest, out bit<1> result) {
            result = stored_digest == digest ? 1w1 : 1w0;
            stored_digest = digest;
        }
    };

    apply {
        if (fabric_md.int_mirror_md.report_type == IntReportType_t.DROP) {
            digest = digester.get({ // burp!
                fabric_md.int_mirror_md.flow_hash,
                fabric_md.int_mirror_md.ig_tstamp[31:30]
            });
            flag = filter_get_and_set1.execute(fabric_md.int_mirror_md.flow_hash[31:16]);
            flag = flag | filter_get_and_set2.execute(fabric_md.int_mirror_md.flow_hash[15:0]);
            // Drop the report if we already report it within a period of time.
            if (flag == 1) {
                eg_dprsr_md.drop_ctl = 1;
                exit;
            }
        }
    }
}

control IntIngress (
    inout parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    action mark_to_report() {
        fabric_md.bridged.int_bmd.report_type = IntReportType_t.LOCAL;
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
            mark_to_report;
            @defaultonly nop();
        }
        const default_action = nop();
        const size = INT_WATCHLIST_TABLE_SIZE;
    }

    action report_drop(bit<32> switch_id) {
        fabric_md.bridged.int_bmd.report_type = IntReportType_t.DROP;
        ig_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INT_REPORT;
        fabric_md.int_mirror_md.setValid();
        fabric_md.int_mirror_md.bmd_type = BridgedMdType_t.INGRESS_MIRROR;
        fabric_md.int_mirror_md.mirror_type = FabricMirrorType_t.INT_REPORT;
        fabric_md.int_mirror_md.report_type = IntReportType_t.DROP;
        fabric_md.int_mirror_md.switch_id = switch_id;
        fabric_md.int_mirror_md.ig_port = (bit<16>)ig_intr_md.ingress_port;
        fabric_md.int_mirror_md.ip_eth_type = fabric_md.bridged.ip_eth_type;
        fabric_md.int_mirror_md.eg_port = (bit<16>)ig_tm_md.ucast_egress_port;
        fabric_md.int_mirror_md.queue_id = (bit<8>)ig_tm_md.qid;
        fabric_md.int_mirror_md.flow_hash = fabric_md.bridged.flow_hash;
#ifdef WITH_SPGW
        fabric_md.int_mirror_md.strip_gtpu = (bit<1>)(hdr.gtpu.isValid());
#endif // WITH_SPGW
    }

    action report_drop_with_reason(bit<32> switch_id, bit<8> drop_reason) {
        report_drop(switch_id);
        fabric_md.int_mirror_md.drop_reason = drop_reason;
    }

    table drop_report {
        key = {
            ig_dprsr_md.drop_ctl: ternary @name("drop_ctl");
            ig_tm_md.copy_to_cpu: ternary @name("copy_to_cpu");
            fabric_md.bridged.int_bmd.report_type: ternary @name("int_report_type");
            fabric_md.int_mirror_md.drop_reason: ternary @name("int_drop_reason");
            fabric_md.next_id: ternary @name("next_id");
        }
        actions = {
            report_drop;
            report_drop_with_reason;
        }
        // (1, 0, LOCAL, _, _) -> report_drop(switch_id)
        // (_, _, LOCAL, UNSET, 0) -> report_drop_with_reason(switch_id, NEXT_ID_MISS)
        const size = 2;
    }

    @hidden
    action set_mirror_session_id(MirrorId_t sid) {
        fabric_md.bridged.int_bmd.mirror_session_id = sid;
    }

    @hidden
    table mirror_session_id {
        key = {
            ig_intr_md.ingress_port: ternary;
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
        mirror_session_id.apply();
        if (hdr.ipv4.isValid()) {
            watchlist.apply();
            drop_report.apply();
        }
    }
}

control IntEgress (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    FlowReportFilter() flow_report_filter;
    DropReportFilter() drop_report_filter;

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
    action add_report_fixed_header(mac_addr_t src_mac, mac_addr_t mon_mac,
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
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.report_ipv4.protocol = PROTO_UDP;
        hdr.report_ipv4.identification = ip_id_gen.get();
        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;
        hdr.report_udp.setValid();
        hdr.report_udp.dport = mon_port;
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 0;
        hdr.report_fixed_header.rsvd = 0;
        hdr.report_fixed_header.hw_id = 0;
        hdr.report_fixed_header.seq_no = 0;
    }

    action do_local_report_encap(mac_addr_t src_mac, mac_addr_t mon_mac,
                                 ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                 l4_port_t mon_port) {
        add_report_fixed_header(src_mac, mon_mac, src_ip, mon_ip, mon_port);
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        hdr.report_fixed_header.f = 1;
        // The INT mirror parser will initialize both local and drop report header and
        // set them to valid, need to set the drop report header to invalid.
        hdr.drop_report_header.setInvalid();
        hdr.report_ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES
                            + REPORT_FIXED_HEADER_BYTES + LOCAL_REPORT_HEADER_BYTES
                            - REPORT_MIRROR_HEADER_BYTES
                            - ETH_FCS_LEN
                            + eg_intr_md.pkt_length;
        hdr.report_udp.len = UDP_HDR_BYTES + REPORT_FIXED_HEADER_BYTES
                             + LOCAL_REPORT_HEADER_BYTES
                             - REPORT_MIRROR_HEADER_BYTES
                             - ETH_FCS_LEN
                             + eg_intr_md.pkt_length;
    }

    action do_local_report_encap_mpls(mac_addr_t src_mac, mac_addr_t mon_mac,
                                      ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                      l4_port_t mon_port, mpls_label_t mon_label) {
        do_local_report_encap(src_mac, mon_mac, src_ip, mon_ip, mon_port);
        hdr.report_eth_type.value = ETHERTYPE_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.label = mon_label;
        hdr.report_mpls.tc = 0;
        hdr.report_mpls.bos = 1;
        hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;
    }

    action do_drop_report_encap(mac_addr_t src_mac, mac_addr_t mon_mac,
                                 ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                 l4_port_t mon_port) {
        add_report_fixed_header(src_mac, mon_mac, src_ip, mon_ip, mon_port);
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_DROP_HEADER;
        hdr.report_fixed_header.d = 1;
        // The INT mirror parser will initialize both local and drop report header and
        // set them to valid, need to set the local report header to invalid.
        hdr.local_report_header.setInvalid();
        hdr.report_ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES
                            + REPORT_FIXED_HEADER_BYTES + DROP_REPORT_HEADER_BYTES
                            - REPORT_MIRROR_HEADER_BYTES
                            - ETH_FCS_LEN
                            + eg_intr_md.pkt_length;
        hdr.report_udp.len = UDP_HDR_BYTES + REPORT_FIXED_HEADER_BYTES
                             + DROP_REPORT_HEADER_BYTES
                             - REPORT_MIRROR_HEADER_BYTES
                             - ETH_FCS_LEN
                             + eg_intr_md.pkt_length;
    }

    action do_drop_report_encap_mpls(mac_addr_t src_mac, mac_addr_t mon_mac,
                                 ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                 l4_port_t mon_port, mpls_label_t mon_label) {
        do_drop_report_encap(src_mac, mon_mac, src_ip, mon_ip, mon_port);
        hdr.report_eth_type.value = ETHERTYPE_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.label = mon_label;
        hdr.report_mpls.tc = 0;
        hdr.report_mpls.bos = 1;
        hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;
    }

    // A table to encap the mirrored packet to an INT report.
    table report {
        // when we are parsing the regular ingress to egress packet,
        // the `int_mirror_md` will be undefined, add `bmd_type` match key to ensure we
        // are handling the right packet type.
        key = {
            fabric_md.bridged.bmd_type: exact @name("bmd_type");
            fabric_md.int_mirror_md.mirror_type: exact @name("mirror_type");
            fabric_md.int_mirror_md.report_type: exact @name("int_report_type");
        }
        actions = {
            do_local_report_encap;
            do_local_report_encap_mpls;
            do_drop_report_encap;
            do_drop_report_encap_mpls;
            @defaultonly nop();
        }
        default_action = nop;
        const size = 6; // Flow, Drop, and Queue report
                        // times bridged metadata types(IN/EGRESS_MIRROR)
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

    action set_metadata(bit<32> switch_id) {
        eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INT_REPORT;
        fabric_md.int_mirror_md.setValid();
        fabric_md.int_mirror_md.bmd_type = BridgedMdType_t.EGRESS_MIRROR;
        fabric_md.int_mirror_md.mirror_type = FabricMirrorType_t.INT_REPORT;
        fabric_md.int_mirror_md.report_type = fabric_md.bridged.int_bmd.report_type;
        fabric_md.int_mirror_md.switch_id = switch_id;
        fabric_md.int_mirror_md.ig_port = (bit<16>)fabric_md.bridged.ig_port;
        fabric_md.int_mirror_md.eg_port = (bit<16>)eg_intr_md.egress_port;
        fabric_md.int_mirror_md.queue_id = (bit<8>)eg_intr_md.egress_qid;
        fabric_md.int_mirror_md.queue_occupancy = (bit<24>)eg_intr_md.enq_qdepth;
        fabric_md.int_mirror_md.ig_tstamp = fabric_md.bridged.ig_tstamp[31:0];
        fabric_md.int_mirror_md.eg_tstamp = eg_prsr_md.global_tstamp[31:0];
        fabric_md.int_mirror_md.ip_eth_type = fabric_md.bridged.ip_eth_type;
#ifdef WITH_SPGW
        fabric_md.int_mirror_md.strip_gtpu = (bit<1>)(hdr.gtpu.isValid());
#endif // WITH_SPGW
    }

    // A table which initialize the INT mirror metadata.
    table int_metadata {
        key = {
            fabric_md.bridged.int_bmd.report_type: exact @name("int_report_type");
        }
        actions = {
            set_metadata;
            @defaultonly nop();
        }
        const default_action = nop();
        const size = 3; // Flow, Drop, Queue
    }

    apply {
        drop_report_filter.apply(hdr, fabric_md, eg_dprsr_md);
        if (report.apply().hit) {
            // The packet is a mirror packet for INT report.
            // Fix the ethertype, the reason we need to fix the ether type is because we
            // may strip the MPLS header from the parser, and the ethertype will still be
            // MPLS instead of real one.
            hdr.eth_type.value = fabric_md.int_mirror_md.ip_eth_type;
            report_seq_no_and_hw_id.apply();
            // Remove the INT mirror metadata to prevent egress mirroring again.
            eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
#ifdef WITH_SPGW
            if (fabric_md.int_mirror_md.strip_gtpu == 1) {
                // We need to remove length of IP, UDP, and GTPU headers
                // since we only monitor the packet inside the GTP tunnel.
                hdr.report_ipv4.total_len = hdr.report_ipv4.total_len
                    - (IPV4_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES);
                hdr.report_udp.len = hdr.report_udp.len
                    - (IPV4_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES);
            }
#endif // WITH_SPGW
            if (fabric_md.mpls_stripped == 1) {
                // We need to remove length of MPLS since we don't include MPLS
                // header in INT report.
                // TODO: support IPv6
                hdr.report_ipv4.total_len = hdr.report_ipv4.total_len
                    - MPLS_HDR_BYTES;
                hdr.report_udp.len = hdr.report_udp.len
                    - MPLS_HDR_BYTES;
            }
            // Reports don't need to go through the rest of the egress pipe.
            exit;
        } else {
            if (int_metadata.apply().hit) {
                flow_report_filter.apply(hdr, fabric_md, eg_intr_md, eg_prsr_md, eg_dprsr_md);
            }
        }
    }
}
#endif
