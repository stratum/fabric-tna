// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_MAIN__
#define __INT_MAIN__

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

control IntWatchlist(inout ingress_headers_t         hdr,
                     inout fabric_ingress_metadata_t fabric_md,
                     inout standard_metadata_t       standard_md,
                     inout IntReportType_t           preserved_report_type) {

    direct_counter(CounterType.packets_and_bytes) watchlist_counter;

    action mark_to_report() {
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_FLOW;
        preserved_report_type = INT_REPORT_TYPE_FLOW;
        watchlist_counter.count();
    }

    action no_report() {
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_NO_REPORT;
        preserved_report_type = INT_REPORT_TYPE_NO_REPORT;

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

        counters = watchlist_counter;
    }

    apply {
        watchlist.apply();
    }
}

control IntIngress(inout ingress_headers_t         hdr,
                   inout fabric_ingress_metadata_t fabric_md,
                   inout standard_metadata_t       standard_md,
                   inout bit<1>                    drop_ctl) {

    direct_counter(CounterType.packets_and_bytes) drop_report_counter;

    @hidden
    action report_drop() {
        fabric_md.bridged.bmd_type = BridgedMdType_t.INT_INGRESS_DROP;
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_DROP;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.bridged.base.mpls_label = 0; // do not push an MPLS label
#ifdef WITH_SPGW
        fabric_md.bridged.spgw.skip_spgw = true;
#endif // WITH_SPGW
        // In V1model, we use the recirculate primitive, in egress pipeline.

        // The drop flag may be set by other tables, need to reset it so the packet can
        // be forwarded to egress pipeline and be recirculated.
        drop_ctl = 0;
        standard_md.egress_spec = FAKE_V1MODEL_RECIRC_PORT;

        drop_report_counter.count();
    }

    @hidden
    table drop_report {
        key = {
            fabric_md.bridged.int_bmd.report_type: exact @name("int_report_type");
            drop_ctl: exact @name("drop_ctl");
            fabric_md.punt_to_cpu: exact @name("punt_to_cpu");
            fabric_md.egress_port_set: exact @name("egress_port_set");
            standard_md.mcast_grp: ternary @name("mcast_group_id");
        }
        actions = {
            report_drop;
            @defaultonly nop;
        }
        const entries = {
            // Explicit drop. Do not report if we are punting to the CPU, since that is
            // implemented as drop+copy_to_cpu.
            (INT_REPORT_TYPE_FLOW, 1, false, false, _): report_drop();
            (INT_REPORT_TYPE_FLOW, 1, false, true, _): report_drop();
            // Likely a table miss
            (INT_REPORT_TYPE_FLOW, 0, false, false, 0): report_drop();
        }
        const default_action = nop();
        counters = drop_report_counter;
    }

    apply {
        // bmv2 specific: mirror_session_id is set in egress pipeline.
        fabric_md.bridged.int_bmd.egress_port = standard_md.egress_spec;
        fabric_md.bridged.int_bmd.queue_id = 0; //bmv2 has only 1 queue.
        drop_report.apply();

    }
}

control IntEgress (inout v1model_header_t          hdr_v1model,
                   inout fabric_v1model_metadata_t fabric_v1model,
                   inout standard_metadata_t       standard_md) {

    // By default report every 2^30 ns (~1 second)
    const bit<48> DEFAULT_TIMESTAMP_MASK = 0xffffc0000000;
    // or for hop latency changes greater than 2^8 ns
    const bit<32> DEFAULT_HOP_LATENCY_MASK = 0xffffff00;

    egress_headers_t hdr = hdr_v1model.egress;
    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;

    direct_counter(CounterType.packets_and_bytes) report_counter;
    direct_counter(CounterType.packets_and_bytes) int_metadata_counter;

    // bmv2 specific. Only one queue present.
    QueueId_t egress_qid = 0;

    @hidden
    register<bit<32>>(1024) seq_number;

    @hidden
    action get_seq_number (in bit<32> seq_number_idx, out bit<32> result) {
        bit<32> reg = 0;
        seq_number.read(reg, seq_number_idx);
        reg = reg + 1;
        result = reg;
        seq_number.write(seq_number_idx, reg);
    }

    action check_quota() {

    }

    action reset_quota() {

    }

    table queue_latency_thresholds {
        key = {
            // In SD-Fabric, we use the same traffic class<>queue ID mapping for all ports.
            // Hence, there's no need to match on the egress port, we can use the same
            // per-queue thresholds for all ports.
            // in V1model, qid is emulated and has no meaning.
            egress_qid: exact @name("egress_qid");
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
        // Constant fields are initialized in IntTnaEgressParserEmulator control.
        random(hdr.report_ipv4.identification, 0, 0xffff);

        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;
        hdr.report_udp.dport = mon_port;
        get_seq_number((bit<32>)hdr.report_fixed_header.hw_id, hdr.report_fixed_header.seq_no);
        hdr.report_fixed_header.dqf = fabric_md.int_report_md.report_type;
        hdr.common_report_header.switch_id = switch_id;
        hdr.common_report_header.pad1 = 0;
        hdr.common_report_header.pad2 = 0;
        hdr.common_report_header.pad3 = 0;
        // Fix ethertype if we have stripped the MPLS header in the parser.
        hdr.eth_type.value = fabric_md.int_report_md.ip_eth_type;

        fabric_v1model.int_mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
        report_counter.count();
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
        hdr.report_mpls.tc = 0;
        hdr.report_mpls.bos = 0;
        hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;
        hdr.report_mpls.label = mon_label;
    }

    action do_drop_report_encap(ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                l4_port_t mon_port, bit<32> switch_id) {
        _report_encap_common(src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_INT_WIP_IPV4;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_DROP_HEADER;
        hdr.drop_report_header.setValid();
        // If drop_report, need to set the local_report invalid.
        //local_report was setValid() in parser emulator to allow its initialization.
        hdr.local_report_header.setInvalid();
        // hdr.drop_report_header.drop_reason = fabric_v1model.preserved_drop_reason;
        hdr.drop_report_header.drop_reason = fabric_md.bridged.int_bmd.drop_reason;
    }

    action do_drop_report_encap_mpls(ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                     l4_port_t mon_port, mpls_label_t mon_label,
                                     bit<32> switch_id) {
        do_drop_report_encap(src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_INT_WIP_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.tc = 0;
        hdr.report_mpls.bos = 0;
        hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;
        hdr.report_mpls.label = mon_label;
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
        counters = report_counter;
    }

    @hidden
    action init_int_metadata(bit<3> report_type) {
        fabric_md.bridged.int_bmd.mirror_session_id = V1MODEL_INT_MIRROR_SESSION;
        fabric_md.int_report_md.setValid();

        fabric_v1model.int_mirror_type = (bit<3>)FabricMirrorType_t.INT_REPORT;
        fabric_md.int_report_md.bmd_type = BridgedMdType_t.EGRESS_MIRROR;
        fabric_md.int_report_md.mirror_type = FabricMirrorType_t.INT_REPORT;
        fabric_md.int_report_md.report_type = fabric_md.bridged.int_bmd.report_type;
        fabric_md.int_report_md.ig_port = fabric_md.bridged.base.ig_port;
        fabric_md.int_report_md.eg_port =(PortId_t)fabric_v1model.preserved_egress_port;
        fabric_md.int_report_md.queue_id = egress_qid;
        fabric_md.int_report_md.queue_occupancy = standard_md.deq_qdepth;
        fabric_md.int_report_md.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        fabric_md.int_report_md.eg_tstamp = standard_md.egress_global_timestamp[31:0];
        fabric_md.int_report_md.ip_eth_type = fabric_md.bridged.base.ip_eth_type;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;
        // fabric_md.int_report_md.encap_presence set by the parser emulator

        fabric_md.int_report_md.report_type = report_type;
        int_metadata_counter.count();
    }

    // Initializes the INT mirror metadata.
    @hidden
    table int_metadata {
        key = {
            fabric_md.bridged.int_bmd.report_type: exact @name("int_report_type");
            fabric_v1model.drop_ctl: exact @name("drop_ctl");
            fabric_md.int_md.queue_report: exact @name("queue_report");
        }
        actions = {
            init_int_metadata;
            @defaultonly nop();
        }
        const default_action = nop();
        const entries = {
            (INT_REPORT_TYPE_FLOW, 0, false): init_int_metadata(INT_REPORT_TYPE_FLOW);
            // (INT_REPORT_TYPE_FLOW, 0, true): init_int_metadata(INT_REPORT_TYPE_FLOW|INT_REPORT_TYPE_QUEUE);
            (INT_REPORT_TYPE_FLOW, 1, false): init_int_metadata(INT_REPORT_TYPE_DROP);
            // (INT_REPORT_TYPE_FLOW, 1, true): init_int_metadata(INT_REPORT_TYPE_DROP);
            // Packets which are not tracked by the watchlist table
            // (INT_REPORT_TYPE_NO_REPORT, 0, true): init_int_metadata(INT_REPORT_TYPE_QUEUE);
            // (INT_REPORT_TYPE_NO_REPORT, 1, true): init_int_metadata(INT_REPORT_TYPE_QUEUE);
        }
        counters = int_metadata_counter;
    }

    @hidden
    action adjust_ip_udp_len(bit<16> adjust_ip, bit<16> adjust_udp) {
        // This action will be performed when a INT report is recirculated. This is why here
        // we use the canonical header structs (ipv4, udp, etc.) instead of report_ipv4, report_udp, etc.
        hdr_v1model.ingress.ipv4.total_len = fabric_md.pkt_length + adjust_ip;
        hdr_v1model.ingress.udp.len = fabric_md.pkt_length + adjust_udp;
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
        const entries = {
            INT_IS_WIP: adjust_ip_udp_len(INT_WIP_ADJUST_IP_BYTES, INT_WIP_ADJUST_UDP_BYTES);
            INT_IS_WIP_WITH_MPLS: adjust_ip_udp_len(INT_WIP_ADJUST_IP_MPLS_BYTES, INT_WIP_ADJUST_UDP_MPLS_BYTES);
        }
    }

    apply {

        fabric_md.int_md.hop_latency = standard_md.egress_global_timestamp[31:0] - fabric_md.bridged.base.ig_tstamp[31:0];
        fabric_md.int_md.timestamp = standard_md.egress_global_timestamp;

        // Check the queue alert before the config table since we need to check the
        // latency which is not quantized.
        queue_latency_thresholds.apply();

        config.apply();
        hdr.report_fixed_header.hw_id = 4w0 ++ standard_md.egress_spec[8:7];

        if (fabric_md.int_report_md.isValid()) {
            // Packet is mirrored (egress) or an ingress drop.
            report.apply();
        } else {
            // Regular packet. Initialize INT mirror metadata.
            if (int_metadata.apply().hit) {
                // Mirroring the packet. It could work only if clone preserves the metadata structs.
                // The mirrored packet will then generate the report.
                clone_preserving_field_list(CloneType.E2E,
                    (bit<32>)fabric_md.bridged.int_bmd.mirror_session_id,
                    PRESERVE_INT_MD);
            }
        }

        adjust_int_report_hdr_length.apply();

        fabric_v1model.egress = fabric_md;
        hdr_v1model.egress = hdr;
    }
}
#endif
