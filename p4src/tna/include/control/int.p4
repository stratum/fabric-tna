// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_MAIN__
#define __INT_MAIN__

#include "shared/define.p4"
#include "shared/header.p4"

// By default report every 2^30 ns (~1 second)
const bit<48> DEFAULT_TIMESTAMP_MASK = 0xffffc0000000;
// or for hop latency changes greater than 2^8 ns
const bit<32> DEFAULT_HOP_LATENCY_MASK = 0xffffff00;
const queue_report_quota_t DEFAULT_QUEUE_REPORT_QUOTA = 1024;

control FlowReportFilter(
    inout egress_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    Hash<bit<16>>(HashAlgorithm_t.CRC16) digester;
    bit<16> digest;
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
    Register<bit<16>, flow_report_filter_index_t>(1 << FLOW_REPORT_FILTER_WIDTH, 0) filter1;
    @hidden
    Register<bit<16>, flow_report_filter_index_t>(1 << FLOW_REPORT_FILTER_WIDTH, 0) filter2;

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
        if (fabric_md.int_report_md.report_type == INT_REPORT_TYPE_FLOW) {
            digest = digester.get({ // burp!
                fabric_md.bridged.base.ig_port,
                eg_intr_md.egress_port,
                fabric_md.int_md.hop_latency,
                fabric_md.bridged.base.inner_hash,
                fabric_md.int_md.timestamp
            });
            flag = filter_get_and_set1.execute(fabric_md.bridged.base.inner_hash[31:16]);
            flag = flag | filter_get_and_set2.execute(fabric_md.bridged.base.inner_hash[15:0]);
            // Generate report only when ALL register actions detect a change.
            if (flag == 1) {
                eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
            }
        }
    }
}


control DropReportFilter(
    inout egress_headers_t hdr,
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
    Register<bit<16>, drop_report_filter_index_t>(1 << DROP_REPORT_FILTER_WIDTH, 0) filter1;
    @hidden
    Register<bit<16>, drop_report_filter_index_t>(1 << DROP_REPORT_FILTER_WIDTH, 0) filter2;

    // Meaning of the result:
    // 1 digest did NOT change
    // 0 change detected
    @reduction_or_group("filter")
    RegisterAction<bit<16>, drop_report_filter_index_t, bit<1>>(filter1) filter_get_and_set1 = {
        void apply(inout bit<16> stored_digest, out bit<1> result) {
            result = stored_digest == digest ? 1w1 : 1w0;
            stored_digest = digest;
        }
    };

    @reduction_or_group("filter")
    RegisterAction<bit<16>, drop_report_filter_index_t, bit<1>>(filter2) filter_get_and_set2 = {
        void apply(inout bit<16> stored_digest, out bit<1> result) {
            result = stored_digest == digest ? 1w1 : 1w0;
            stored_digest = digest;
        }
    };

    apply {
        // This control is applied to all pkts, but we filter only INT mirrors.
        if (fabric_md.int_report_md.isValid() &&
                fabric_md.int_report_md.report_type == INT_REPORT_TYPE_DROP) {
            digest = digester.get({ // burp!
                fabric_md.int_report_md.flow_hash,
                fabric_md.int_md.timestamp
            });
            flag = filter_get_and_set1.execute(fabric_md.int_report_md.flow_hash[31:16]);
            flag = flag | filter_get_and_set2.execute(fabric_md.int_report_md.flow_hash[15:0]);
            // Drop the report if we already report it within a period of time.
            if (flag == 1) {
                eg_dprsr_md.drop_ctl = 1;
                exit;
            }
        }
    }
}

control IntWatchlist(
    inout ingress_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
#ifdef WITH_DEBUG
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) watchlist_counter;
#endif // WITH_DEBUG

    action mark_to_report() {
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_FLOW;
        ig_tm_md.deflect_on_drop = 1;
#ifdef WITH_DEBUG
        watchlist_counter.count();
#endif // WITH_DEBUG
    }

    action no_report() {
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_NO_REPORT;
    }

    // Required by the control plane to distinguish entries used to exclude the INT
    // report flow to the collector.
    action no_report_collector() {
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_NO_REPORT;
    }

    table watchlist {
        key = {
            fabric_md.lkp.is_ipv4  : exact   @name("ipv4_valid");
            fabric_md.lkp.ipv4_src : ternary @name("ipv4_src");
            fabric_md.lkp.ipv4_dst : ternary @name("ipv4_dst");
            fabric_md.lkp.ip_proto : ternary @name("ip_proto");
            fabric_md.lkp.l4_sport : range   @name("l4_sport");
            fabric_md.lkp.l4_dport : range   @name("l4_dport");
        }
        actions = {
            mark_to_report;
            no_report_collector;
            @defaultonly no_report();
        }
        const default_action = no_report();
        const size = INT_WATCHLIST_TABLE_SIZE;
#ifdef WITH_DEBUG
        counters = watchlist_counter;
#endif // WITH_DEBUG
    }

    apply {
        watchlist.apply();
    }
}

control IntIngress(
    inout ingress_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

#ifdef WITH_DEBUG
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) drop_report_counter;
#endif // WITH_DEBUG


    @hidden
    action report_drop() {
        fabric_md.bridged.bmd_type = BridgedMdType_t.INT_INGRESS_DROP;
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_DROP;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.bridged.base.mpls_label = 0; // do not push an MPLS label
#ifdef WITH_SPGW
        fabric_md.bridged.spgw.skip_spgw = true;
#endif // WITH_SPGW
        // Redirect to the recirculation port of the pipeline
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port[8:7] ++ RECIRC_PORT_NUMBER;

        // The drop flag may be set by other tables, need to reset it so the packet can
        // be forward to the recirculation port.
        ig_dprsr_md.drop_ctl = 0;
#ifdef WITH_DEBUG
        drop_report_counter.count();
#endif // WITH_DEBUG
    }

    @hidden
    table drop_report {
        key = {
            fabric_md.bridged.int_bmd.report_type: exact @name("int_report_type");
            ig_dprsr_md.drop_ctl: exact @name("drop_ctl");
            fabric_md.punt_to_cpu: exact @name("punt_to_cpu");
            fabric_md.egress_port_set: ternary @name("egress_port_set");
            ig_tm_md.mcast_grp_a: ternary @name("mcast_group_id");
        }
        actions = {
            report_drop;
            @defaultonly nop;
        }
        const size = 2;
        const entries = {
            // Explicit drop. Do not report if we are punting to the CPU, since that is
            // implemented as drop+copy_to_cpu.
            (INT_REPORT_TYPE_FLOW, 1, false, _, _): report_drop();
            // Likely a table miss
            (INT_REPORT_TYPE_FLOW, 0, false, false, 0): report_drop();
        }
        const default_action = nop();
#ifdef WITH_DEBUG
        counters = drop_report_counter;
#endif // WITH_DEBUG
    }

    apply {
        // Here we use 0b10000000xx as the mirror session ID where "xx" is the 2-bit
        // pipeline number(0~3).
        // FIXME: set mirror_session_id in egress to save bmd resources
        fabric_md.bridged.int_bmd.mirror_session_id = INT_MIRROR_SESSION_BASE ++ ig_intr_md.ingress_port[8:7];
        // When the traffic manager deflects a packet, the egress port and queue id
        // of egress intrinsic metadata will be the port and queue used for deflection.
        // We need to bridge the egress port and queue id from ingress to the egress
        // parser to initialize the INT drop report.
        fabric_md.bridged.int_bmd.egress_port = ig_tm_md.ucast_egress_port;
        fabric_md.bridged.int_bmd.queue_id = ig_tm_md.qid;
        drop_report.apply();
    }
}

control IntEgress (
    inout egress_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    FlowReportFilter() flow_report_filter;
    DropReportFilter() drop_report_filter;
    queue_report_filter_index_t queue_report_filter_index;

#ifdef WITH_DEBUG
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) report_counter;
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) int_metadata_counter;
#endif // WITH_DEBUG

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

    Register<queue_report_quota_t, queue_report_filter_index_t>(1 << QUEUE_REPORT_FILTER_WIDTH, DEFAULT_QUEUE_REPORT_QUOTA) queue_report_quota;
    RegisterAction<queue_report_quota_t, queue_report_filter_index_t, bool>(queue_report_quota) check_quota_and_report = {
        void apply(inout queue_report_quota_t quota, out bool report) {
            if (quota > 0) {
                quota = quota - 1;
                report = true;
            } else {
                report = false;
            }
        }
    };

    RegisterAction<queue_report_quota_t, queue_report_filter_index_t, bool>(queue_report_quota) reset_report_quota = {
        void apply(inout queue_report_quota_t quota, out bool report) {
            quota = DEFAULT_QUEUE_REPORT_QUOTA;
            report = false;
        }
    };

    action check_quota() {
        fabric_md.int_md.queue_report = check_quota_and_report.execute(queue_report_filter_index);
    }

    action reset_quota() {
        fabric_md.int_md.queue_report = reset_report_quota.execute(queue_report_filter_index);
    }

    table queue_latency_thresholds {
        key = {
            // In SD-Fabric, we use the same traffic class<>queue ID mapping for all ports.
            // Hence, there's no need to match on the egress port, we can use the same
            // per-queue thresholds for all ports.
            eg_intr_md.egress_qid: exact @name("egress_qid");
            fabric_md.int_md.hop_latency[31:16]: range @name("hop_latency_upper");
            fabric_md.int_md.hop_latency[15:0]: range @name("hop_latency_lower");
        }
        actions = {
            check_quota;
            reset_quota;
            @defaultonly nop;
        }
        default_action = nop();
        const size = INT_QUEUE_REPORT_TABLE_SIZE;
    }

    action set_config(bit<32> hop_latency_mask, bit<48> timestamp_mask) {
        fabric_md.int_md.hop_latency = fabric_md.int_md.hop_latency & hop_latency_mask;
        fabric_md.int_md.timestamp = fabric_md.int_md.timestamp & timestamp_mask;
    }

    table config {
        actions = {
            @defaultonly set_config;
        }
        default_action = set_config(DEFAULT_HOP_LATENCY_MASK, DEFAULT_TIMESTAMP_MASK);
        const size = 1;
    }

    @hidden
    action _report_encap_common(ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                l4_port_t mon_port, bit<32> switch_id) {
        // Constant fields are initialized in int_mirror_parser.p4.
        hdr.report_ipv4.identification = ip_id_gen.get();
        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;
        hdr.report_udp.dport = mon_port;
        hdr.report_fixed_header.seq_no = get_seq_number.execute(hdr.report_fixed_header.hw_id);
        hdr.report_fixed_header.dqf = fabric_md.int_report_md.report_type;
        hdr.common_report_header.switch_id = switch_id;
        // This is required to correct a (buggy?) @flexible allocation of
        // bridged metadata that causes non-zero values to be extracted by the
        // egress parser onto the below padding fields.
        hdr.common_report_header.pad1 = 0;
        hdr.common_report_header.pad2 = 0;
        hdr.common_report_header.pad3 = 0;
        // Fix ethertype if we have stripped the MPLS header in the parser.
        hdr.eth_type.value = fabric_md.int_report_md.ip_eth_type;
        // Remove the INT mirror metadata to prevent egress mirroring again.
        eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
#ifdef WITH_DEBUG
        report_counter.count();
#endif // WITH_DEBUG
    }

    action do_local_report_encap(ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                 l4_port_t mon_port, bit<32> switch_id) {
        _report_encap_common(src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_INT_WIP_IPV4;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        hdr.local_report_header.setValid();
    }

    action do_local_report_encap_mpls(ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                      l4_port_t mon_port, mpls_label_t mon_label,
                                      bit<32> switch_id) {
        do_local_report_encap(src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_INT_WIP_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.bos = 1;
        hdr.report_mpls.label = mon_label;
    }

    action do_drop_report_encap(ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                l4_port_t mon_port, bit<32> switch_id) {
        _report_encap_common(src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_INT_WIP_IPV4;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_DROP_HEADER;
        hdr.drop_report_header.setValid();
    }

    action do_drop_report_encap_mpls(ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                     l4_port_t mon_port, mpls_label_t mon_label,
                                     bit<32> switch_id) {
        do_drop_report_encap(src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_INT_WIP_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.bos = 1;
        hdr.report_mpls.label = mon_label;
    }

    // Transforms mirrored packets into INT report packets.
    table report {
        // when we are parsing the regular ingress to egress packet,
        // the `int_report_md` will be undefined, add `bmd_type` match key to ensure we
        // are handling the right packet type.
        key = {
            fabric_md.int_report_md.bmd_type: exact @name("bmd_type");
            fabric_md.int_report_md.mirror_type: exact @name("mirror_type");
            fabric_md.int_report_md.report_type: exact @name("int_report_type");
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
        // entries = {
        //      (INT_INGRESS_DROP, INVALID, DROP): ingress drop report
        //      (EGRESS_MIRROR, INT_REPORT, DROP): egress drop report
        //      (DEFLECTED, INVALID, FLOW): deflect on drop report
        //      (EGRESS_MIRROR, INT_REPORT, FLOW): flow report
        //      (EGRESS_MIRROR, INT_REPORT, QUEUE): queue report
        //      (EGRESS_MIRROR, INT_REPORT, QUEUE|FLOW): flow+queue report
        // }
#ifdef WITH_DEBUG
        counters = report_counter;
#endif // WITH_DEBUG
    }

    @hidden
    action init_int_metadata(bit<3> report_type) {
        eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INT_REPORT;
        fabric_md.int_report_md.bmd_type = BridgedMdType_t.EGRESS_MIRROR;
        fabric_md.int_report_md.mirror_type = FabricMirrorType_t.INT_REPORT;
        fabric_md.int_report_md.report_type = fabric_md.bridged.int_bmd.report_type;
        fabric_md.int_report_md.ig_port = fabric_md.bridged.base.ig_port;
        fabric_md.int_report_md.eg_port = eg_intr_md.egress_port;
        fabric_md.int_report_md.queue_id = eg_intr_md.egress_qid;
        fabric_md.int_report_md.queue_occupancy = eg_intr_md.enq_qdepth;
        fabric_md.int_report_md.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        fabric_md.int_report_md.eg_tstamp = eg_prsr_md.global_tstamp[31:0];
        fabric_md.int_report_md.ip_eth_type = fabric_md.bridged.base.ip_eth_type;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;
        // fabric_md.int_report_md.encap_presence set by the parser

        fabric_md.int_report_md.report_type = report_type;
#ifdef WITH_DEBUG
        int_metadata_counter.count();
#endif // WITH_DEBUG
    }

    // Initializes the INT mirror metadata.
    @hidden
    table int_metadata {
        key = {
            fabric_md.bridged.int_bmd.report_type: exact @name("int_report_type");
            eg_dprsr_md.drop_ctl: exact @name("drop_ctl");
            fabric_md.int_md.queue_report: exact @name("queue_report");
        }
        actions = {
            init_int_metadata;
            @defaultonly nop();
        }
        const default_action = nop();
        const size = 6;
        const entries = {
            (INT_REPORT_TYPE_FLOW, 0, false): init_int_metadata(INT_REPORT_TYPE_FLOW);
            (INT_REPORT_TYPE_FLOW, 0, true): init_int_metadata(INT_REPORT_TYPE_FLOW|INT_REPORT_TYPE_QUEUE);
            (INT_REPORT_TYPE_FLOW, 1, false): init_int_metadata(INT_REPORT_TYPE_DROP);
            (INT_REPORT_TYPE_FLOW, 1, true): init_int_metadata(INT_REPORT_TYPE_DROP);
            // Packets which does not tracked by the watchlist table
            (INT_REPORT_TYPE_NO_REPORT, 0, true): init_int_metadata(INT_REPORT_TYPE_QUEUE);
            (INT_REPORT_TYPE_NO_REPORT, 1, true): init_int_metadata(INT_REPORT_TYPE_QUEUE);
        }

#ifdef WITH_DEBUG
        counters = int_metadata_counter;
#endif // WITH_DEBUG
    }

    @hidden
    action adjust_ip_udp_len(bit<16> adjust_ip, bit<16> adjust_udp) {
        hdr.ipv4.total_len = fabric_md.pkt_length + adjust_ip;
        hdr.udp.len = fabric_md.pkt_length + adjust_udp;
    }

    @hidden
    table adjust_int_report_hdr_length {
        key = {
            fabric_md.bridged.int_bmd.wip_type: exact @name("is_int_wip");
        }

        actions = {
            @defaultonly nop();
            adjust_ip_udp_len;
        }
        const default_action = nop();
        const size = 2;
        const entries = {
            INT_IS_WIP: adjust_ip_udp_len(INT_WIP_ADJUST_IP_BYTES, INT_WIP_ADJUST_UDP_BYTES);
            INT_IS_WIP_WITH_MPLS: adjust_ip_udp_len(INT_WIP_ADJUST_IP_MPLS_BYTES, INT_WIP_ADJUST_UDP_MPLS_BYTES);
        }
    }

    apply {
        fabric_md.int_md.hop_latency = eg_prsr_md.global_tstamp[31:0] - fabric_md.bridged.base.ig_tstamp[31:0];
        fabric_md.int_md.timestamp = eg_prsr_md.global_tstamp;
        // Here we use the lower 7-bit of port number with qid as the register index
        // Only 7-bit because registers are independent between pipes.
        queue_report_filter_index = eg_intr_md.egress_port[6:0] ++ eg_intr_md.egress_qid;

        // Check the queue alert before the config table since we need to check the
        // latency which is not quantized.
        queue_latency_thresholds.apply();

        config.apply();
        hdr.report_fixed_header.hw_id = 4w0 ++ eg_intr_md.egress_port[8:7];

        // Filtering for drop reports is done after mirroring to handle all drop
        // cases with one filter:
        // - drop by ingress tables (ingress mirroring)
        // - drop by egress table (egress mirroring)
        // - drop by the traffic manager (deflect on drop, TODO)
        // The penalty we pay for using one filter is that we might congest the
        // mirroring facilities and recirculation port.
        // FIXME: should we worry about this, or can we assume that packet drops
        //  are a rare event? What happens if a 100Gbps flow gets dropped by an
        //  ingress/egress table (e.g., routing table miss, egress vlan table
        //  miss, etc.)?
        drop_report_filter.apply(hdr, fabric_md, eg_dprsr_md);

        if (fabric_md.int_report_md.isValid()) {
            // Packet is mirrored (egress or deflected) or an ingress drop.
            report.apply();
        } else {
            // Regular packet. Initialize INT mirror metadata but let
            // filter decide whether to generate a mirror or not.
            if (int_metadata.apply().hit) {
                flow_report_filter.apply(hdr, fabric_md, eg_intr_md, eg_prsr_md, eg_dprsr_md);
            }
        }

        adjust_int_report_hdr_length.apply();
    }
}
#endif
