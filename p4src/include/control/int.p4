// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_MAIN__
#define __INT_MAIN__

#include "../define.p4"
#include "../header.p4"

// By default report every 2^30 ns (~1 second)
const bit<48> DEFAULT_TIMESTAMP_MASK = 0xffffc0000000;
// or for hop latency changes greater than 2^8 ns
const bit<32> DEFAULT_HOP_LATENCY_MASK = 0xffffff00;

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
        if (fabric_md.int_report_md.report_type == IntReportType_t.LOCAL) {
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
                fabric_md.int_report_md.report_type == IntReportType_t.DROP) {
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
        fabric_md.bridged.int_bmd.report_type = IntReportType_t.LOCAL;
        ig_tm_md.deflect_on_drop = 1;
#ifdef WITH_DEBUG
        watchlist_counter.count();
#endif // WITH_DEBUG
    }

    action no_report() {
        fabric_md.bridged.int_bmd.report_type = IntReportType_t.NO_REPORT;
    }

    // Required by the control plane to distinguish entries used to exclude the INT
    // report flow to the collector.
    action no_report_collector() {
        fabric_md.bridged.int_bmd.report_type = IntReportType_t.NO_REPORT;
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
        fabric_md.bridged.int_bmd.report_type = IntReportType_t.DROP;
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
            (IntReportType_t.LOCAL, 1, false, _, _): report_drop();
            // Likely a table miss
            (IntReportType_t.LOCAL, 0, false, false, 0): report_drop();
        }
        const default_action = nop();
#ifdef WITH_DEBUG
        counters = drop_report_counter;
#endif // WITH_DEBUG
    }

    apply {
        // Here we use 0b10000000xx as the mirror session ID where "xx" is the 2-bit
        // pipeline number(0~3).
        fabric_md.bridged.int_bmd.mirror_session_id = INT_MIRROR_SESSION_BASE ++ ig_intr_md.ingress_port[8:7];
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
    action _report_encap_common(mac_addr_t src_mac, mac_addr_t mon_mac,
                                ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                l4_port_t mon_port, bit<32> switch_id) {
        // Constant fields are initialized in int_mirror_parser.p4.
        hdr.report_ethernet.dst_addr = mon_mac;
        hdr.report_ethernet.src_addr = src_mac;
        hdr.report_ipv4.identification = ip_id_gen.get();
        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;
        hdr.report_udp.dport = mon_port;
        hdr.report_fixed_header.seq_no = get_seq_number.execute(hdr.report_fixed_header.hw_id);
        hdr.common_report_header.switch_id = switch_id;
        // Fix ethertype if we have stripped the MPLS header in the parser.
        hdr.eth_type.value = fabric_md.int_report_md.ip_eth_type;
        // Remove the INT mirror metadata to prevent egress mirroring again.
        eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
#ifdef WITH_DEBUG
        report_counter.count();
#endif // WITH_DEBUG
    }

    action do_local_report_encap(mac_addr_t src_mac, mac_addr_t mon_mac,
                                 ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                 l4_port_t mon_port, bit<32> switch_id) {
        _report_encap_common(src_mac, mon_mac, src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_IPV4;
        hdr.report_ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES
                        + REPORT_FIXED_HEADER_BYTES + LOCAL_REPORT_HEADER_BYTES
                        + ETH_HDR_BYTES + fabric_md.int_ipv4_len;
        hdr.report_udp.len = UDP_HDR_BYTES
                        + REPORT_FIXED_HEADER_BYTES + LOCAL_REPORT_HEADER_BYTES
                        + ETH_HDR_BYTES + fabric_md.int_ipv4_len;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        hdr.report_fixed_header.d = 0;
        hdr.report_fixed_header.q = 0;
        hdr.report_fixed_header.f = 1;
        hdr.local_report_header.setValid();
    }

    action do_local_report_encap_mpls(mac_addr_t src_mac, mac_addr_t mon_mac,
                                      ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                      l4_port_t mon_port, mpls_label_t mon_label,
                                      bit<32> switch_id) {
        do_local_report_encap(src_mac, mon_mac, src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.label = mon_label;
    }

    action do_drop_report_encap(mac_addr_t src_mac, mac_addr_t mon_mac,
                                ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                l4_port_t mon_port, bit<32> switch_id) {
        _report_encap_common(src_mac, mon_mac, src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_IPV4;
        hdr.report_ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES
                        + REPORT_FIXED_HEADER_BYTES + DROP_REPORT_HEADER_BYTES
                        + ETH_HDR_BYTES + fabric_md.int_ipv4_len;
        hdr.report_udp.len = UDP_HDR_BYTES
                        + REPORT_FIXED_HEADER_BYTES + DROP_REPORT_HEADER_BYTES
                        + ETH_HDR_BYTES + fabric_md.int_ipv4_len;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_DROP_HEADER;
        hdr.report_fixed_header.d = 1;
        hdr.report_fixed_header.q = 0;
        hdr.report_fixed_header.f = 0;
        hdr.drop_report_header.setValid();
    }

    action do_drop_report_encap_mpls(mac_addr_t src_mac, mac_addr_t mon_mac,
                                     ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                     l4_port_t mon_port, mpls_label_t mon_label,
                                     bit<32> switch_id) {
        do_drop_report_encap(src_mac, mon_mac, src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_MPLS;
        hdr.report_mpls.setValid();
        hdr.report_mpls.label = mon_label;
    }

    action do_deflect_on_drop_report_encap(mac_addr_t src_mac, mac_addr_t mon_mac,
                                ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                l4_port_t mon_port, bit<32> switch_id) {
        do_drop_report_encap(src_mac, mon_mac, src_ip, mon_ip, mon_port, switch_id);
        hdr.common_report_header.setValid();
        hdr.common_report_header.ig_port = fabric_md.bridged.base.ig_port;
        hdr.common_report_header.eg_port = eg_intr_md.egress_port;
        hdr.common_report_header.queue_id = eg_intr_md.egress_qid;
        hdr.drop_report_header.setValid();
        hdr.drop_report_header.drop_reason = IntDropReason_t.DROP_REASON_TRAFFIC_MANAGER;
    }

    action do_deflect_on_drop_report_encap_mpls(mac_addr_t src_mac, mac_addr_t mon_mac,
                                     ipv4_addr_t src_ip, ipv4_addr_t mon_ip,
                                     l4_port_t mon_port, mpls_label_t mon_label,
                                     bit<32> switch_id) {
        do_deflect_on_drop_report_encap(src_mac, mon_mac, src_ip, mon_ip, mon_port, switch_id);
        hdr.report_eth_type.value = ETHERTYPE_MPLS;
        hdr.report_mpls.setValid();
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
            do_deflect_on_drop_report_encap;
            do_deflect_on_drop_report_encap_mpls;
            @defaultonly nop();
        }
        default_action = nop;
        const size = 6; // Flow, Drop, and Queue report
                        // times bridged metadata types(IN/EGRESS_MIRROR)
        // entries = {
        //      (INT_INGRESS_DROP, INVALID, DROP): ingress drop report
        //      (EGRESS_MIRROR, INT_REPORT, DROP): egress drop report
        //      (DEFLECTED, INVALID, LOCAL): deflect on drop report
        //      (EGRESS_MIRROR, INT_REPORT, LOCAL): local report
        //      (EGRESS_MIRROR, INT_REPORT, QUEUE): queue report
        // }
#ifdef WITH_DEBUG
        counters = report_counter;
#endif // WITH_DEBUG
    }

    @hidden
    action set_report_metadata() {
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
        // fabric_md.int_report_md.gtpu_presence set by the parser
    }

    @hidden
    action report_local() {
        set_report_metadata();
        fabric_md.int_report_md.report_type = IntReportType_t.LOCAL;
#ifdef WITH_DEBUG
        int_metadata_counter.count();
#endif // WITH_DEBUG
    }

    @hidden
    action report_drop() {
        set_report_metadata();
        fabric_md.int_report_md.report_type = IntReportType_t.DROP;
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
        }
        actions = {
            report_local;
            report_drop;
            @defaultonly nop();
        }
        const default_action = nop();
        const size = 2;
        const entries = {
            (IntReportType_t.LOCAL, 1): report_drop();
            (IntReportType_t.LOCAL, 0): report_local();
        }

#ifdef WITH_DEBUG
        counters = int_metadata_counter;
#endif // WITH_DEBUG
    }

    apply {
        fabric_md.int_md.hop_latency = eg_prsr_md.global_tstamp[31:0] - fabric_md.bridged.base.ig_tstamp[31:0];
        fabric_md.int_md.timestamp = eg_prsr_md.global_tstamp;

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
    }
}
#endif
