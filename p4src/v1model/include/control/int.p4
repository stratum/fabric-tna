// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_MAIN__
#define __INT_MAIN__

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

// By default report every 2^30 ns (~1 second)
const bit<48> DEFAULT_TIMESTAMP_MASK = 0xffffc0000000;
// or for hop latency changes greater than 2^8 ns
const bit<32> DEFAULT_HOP_LATENCY_MASK = 0xffffff00;
const queue_report_quota_t DEFAULT_QUEUE_REPORT_QUOTA = 1024;

// bmv2 specific for hash function.
const bit<32> max = 0xFFFF;
const bit<32> base = 0;

#define IS_DROP_CTL_SET(std_meta) (std_meta.egress_spec == 511)


control FlowReportFilter(
    inout egress_headers_t hdr,
    // inout fabric_egress_metadata_t fabric_md,
    inout fabric_v1model_metadata_t fabric_v1model,
    inout standard_metadata_t standard_md
    // in    egress_intrinsic_metadata_t eg_intr_md,
    // in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    // inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
    ) {

    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;
    bit<16> digest = 0;
    bit<16> stored_digest = 0;
    bit<1> flag = 0;

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
    register<bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH) filter1;
    @hidden
    register<bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH) filter2;

    // Meaning of the result:
    // 1 digest did NOT change
    // 0 change detected
    // @reduction_or_group("filter")
    // RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter1) filter_get_and_set1 = {
    //     void apply(inout bit<16> stored_digest, out bit<1> result) {
    //         result = stored_digest == digest ? 1w1 : 1w0;
    //         stored_digest = digest;
    //     }
    // };

    // @reduction_or_group("filter")
    // RegisterAction<bit<16>, flow_report_filter_index_t, bit<1>>(filter2) filter_get_and_set2 = {
    //     void apply(inout bit<16> stored_digest, out bit<1> result) {
    //         result = stored_digest == digest ? 1w1 : 1w0;
    //         stored_digest = digest;
    //     }
    // };

    apply {
        if (fabric_md.int_report_md.report_type == INT_REPORT_TYPE_FLOW) {
            hash(
                digest,
                HashAlgorithm.crc16,
                base,
                {
                    fabric_md.bridged.base.ig_port,
                    standard_md.egress_spec,
                    fabric_md.int_md.hop_latency,
                    fabric_md.bridged.base.inner_hash,
                    fabric_md.int_md.timestamp
                },
                max
            );

            // filter1 get and set
            filter1.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[31:16]);
            flag = digest == stored_digest ? 1w1 : 1w0;
            filter1.write((bit<32>)fabric_md.bridged.base.inner_hash[31:16], digest);
            // filter2 get and set
            filter2.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[15:0]);
            flag = flag | (digest == stored_digest ? 1w1 : 1w0);
            filter2.write((bit<32>)fabric_md.bridged.base.inner_hash[15:0], digest);

            // flag = filter_get_and_set1.execute(fabric_md.bridged.base.inner_hash[31:16]);
            // flag = flag | filter_get_and_set2.execute(fabric_md.bridged.base.inner_hash[15:0]);
            // Generate report only when ALL register actions detect a change.
            if (flag == 1) {
                fabric_v1model.int_mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
                // eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
            }
        }
    }
}


control DropReportFilter(
    inout egress_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    inout standard_metadata_t standard_md
    // inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
    ) {

    bit<16> digest = 0;
    bit<16> stored_digest = 0;
    bit<1> flag = 0;

    // Bloom filter with 2 hash functions storing flow digests. The digest is
    // the hash of:
    // - quantized timestamp (to generate periodic reports).
    // - 5-tuple hash (to detect collisions);
    // We use such filter to reduce the volume of reports that the collector has
    // to ingest.
    @hidden
    register<bit<16>>(1 << DROP_REPORT_FILTER_WIDTH) filter1;
    @hidden
    register<bit<16>>(1 << DROP_REPORT_FILTER_WIDTH) filter2;

    // Meaning of the result:
    // 1 digest did NOT change
    // 0 change detected
    // @reduction_or_group("filter")
    // RegisterAction<bit<16>, drop_report_filter_index_t, bit<1>>(filter1) filter_get_and_set1 = {
    //     void apply(inout bit<16> stored_digest, out bit<1> result) {
    //         result = stored_digest == digest ? 1w1 : 1w0;
    //         stored_digest = digest;
    //     }
    // };

    // @reduction_or_group("filter")
    // RegisterAction<bit<16>, drop_report_filter_index_t, bit<1>>(filter2) filter_get_and_set2 = {
    //     void apply(inout bit<16> stored_digest, out bit<1> result) {
    //         result = stored_digest == digest ? 1w1 : 1w0;
    //         stored_digest = digest;
    //     }
    // };

    apply {
        // This control is applied to all pkts, but we filter only INT mirrors.
        if (fabric_md.int_report_md.isValid() &&
                fabric_md.int_report_md.report_type == INT_REPORT_TYPE_DROP) {
            hash(
                digest,
                HashAlgorithm.crc16,
                base,
                {
                    fabric_md.int_report_md.flow_hash,
                    fabric_md.int_md.timestamp
                },
                max
            );
            // filter 1 get and set
            filter1.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[31:16]);
            flag = digest == stored_digest ? 1w1 : 1w0;
            filter1.write((bit<32>)fabric_md.bridged.base.inner_hash[31:16], digest);
            // filter 2 get and set
            filter2.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[15:0]);
            flag = flag | (digest == stored_digest ? 1w1 : 1w0);
            filter2.write((bit<32>)fabric_md.bridged.base.inner_hash[15:0], digest);

            // flag = filter_get_and_set1.execute(fabric_md.int_report_md.flow_hash[31:16]);
            // flag = flag | filter_get_and_set2.execute(fabric_md.int_report_md.flow_hash[15:0]);
            // Drop the report if we already report it within a period of time.
            if (flag == 1) {
                // eg_dprsr_md.drop_ctl = 1;
                mark_to_drop(standard_md);
                // exit;
            }
        }
    }
}

control IntWatchlist(
    inout ingress_headers_t hdr,
    inout fabric_v1model_metadata_t fabric_v1model,
    inout standard_metadata_t standard_md
    // in    ingress_intrinsic_metadata_t ig_intr_md,
    // inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    // inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
    ) {

    direct_counter(CounterType.packets_and_bytes) watchlist_counter;
    fabric_ingress_metadata_t fabric_md = fabric_v1model.ingress;

    action mark_to_report() {
        fabric_md.bridged.int_bmd.report_type = INT_REPORT_TYPE_FLOW;
        fabric_v1model.int_deflect_on_drop = 1w1;
        // ig_tm_md.deflect_on_drop = 1;

        watchlist_counter.count();
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

        counters = watchlist_counter;
    }

    apply {
        watchlist.apply();
        fabric_v1model.ingress = fabric_md;
    }
}

control IntIngress(
    inout ingress_headers_t hdr,
    inout fabric_v1model_metadata_t fabric_v1model,
    // inout fabric_ingress_metadata_t fabric_md,
    inout standard_metadata_t standard_md
    // in    ingress_intrinsic_metadata_t ig_intr_md,
    // inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    // inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
    ) {

    fabric_ingress_metadata_t fabric_md = fabric_v1model.ingress;
    bit<1> drop_ctl = 0;
    // Convert from bool to int because of ternary match not supporting bool.
    bit<1> egress_port_set = (bit<1>)fabric_md.egress_port_set;
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
        // Redirect to the recirculation port of the pipeline
        // ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port[8:7] ++ RECIRC_PORT_NUMBER;
        // standard_md.egress_spec = standard_md.ingress_port[8:7] ++ RECIRC_PORT_NUMBER; //FIXME bmv2 should invoke recirculate.

        // The drop flag may be set by other tables, need to reset it so the packet can
        // be forward to the recirculation port.
        // ig_dprsr_md.drop_ctl = 0;
        drop_ctl = 0; //FIXME what if mark_to_drop was invoked? should override egress_spec.
        // standard_md.egress_spec = 1;

        drop_report_counter.count();
    }

    @hidden
    table drop_report {
        key = {
            fabric_md.bridged.int_bmd.report_type: exact @name("int_report_type");
            // ig_dprsr_md.drop_ctl: exact @name("drop_ctl");
            drop_ctl: exact @name("drop_ctl");
            fabric_md.punt_to_cpu: exact @name("punt_to_cpu");
            // fabric_md.egress_port_set: ternary @name("egress_port_set");
            egress_port_set: ternary @name("egress_port_set");
            // ig_tm_md.mcast_grp_a: ternary @name("mcast_group_id");
            standard_md.mcast_grp: ternary @name("mcast_group_id");
        }
        actions = {
            report_drop;
            @defaultonly nop;
        }
        const entries = {
            // Explicit drop. Do not report if we are punting to the CPU, since that is
            // implemented as drop+copy_to_cpu.
            (INT_REPORT_TYPE_FLOW, 1, false, _, _): report_drop();
            // Likely a table miss
            (INT_REPORT_TYPE_FLOW, 0, false, 0, 0): report_drop();
        }
        const default_action = nop();
        counters = drop_report_counter;
    }

    apply {
        // Here we use 0b10000000xx as the mirror session ID where "xx" is the 2-bit
        // pipeline number(0~3).
        // fabric_md.bridged.int_bmd.mirror_session_id = INT_MIRROR_SESSION_BASE ++ ig_intr_md.ingress_port[8:7];
        fabric_md.bridged.int_bmd.mirror_session_id = BMV2_INT_MIRROR_SESSION; // for bmv2, use a single mirror session ID.
        // When the traffic manager deflects a packet, the egress port and queue id
        // of egress intrinsic metadata will be the port and queue used for deflection.
        // We need to bridge the egress port and queue id from ingress to the egress
        // parser to initialize the INT drop report.
        // fabric_md.bridged.int_bmd.egress_port = ig_tm_md.ucast_egress_port;
        // fabric_md.bridged.int_bmd.queue_id = ig_tm_md.qid;
        fabric_md.bridged.int_bmd.egress_port = standard_md.egress_spec;
        fabric_md.bridged.int_bmd.queue_id = 0; //bmv2 has only 1 queue.
        drop_report.apply();
        if (drop_ctl == 1) {
            mark_to_drop(standard_md);
        }

        fabric_v1model.ingress = fabric_md;
    }
}

control IntEgressParserEmulator (
    inout v1model_header_t hdr_v1model,
    // inout egress_headers_t hdr,
    inout fabric_v1model_metadata_t fabric_v1model,
    inout standard_metadata_t standard_md) {

// This control wraps all the logic defined within the TNA egress parser.
// It actually does not perform any parsing of the packet.

    egress_headers_t hdr = hdr_v1model.egress;
    // fabric_ingress_metadata_t fabric_md = fabric_v1model.ingress;
    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;

    @hidden
    action drop() {
        mark_to_drop(standard_md);
    }

    @hidden
    action reject() {
        drop();
        exit;
    }

    @hidden
    action set_common_int_headers() {
        // Initialize report headers here to allocate constant fields on the
        // T-PHV (and save on PHV resources).
        /** report_ethernet **/
        hdr.report_ethernet.setValid();
        // hdr.report_ethernet.dst_addr = update later
        // hdr.report_ethernet.src_addr = update later

        /** report_eth_type **/
        hdr.report_eth_type.setValid();
        // hdr.report_eth_type.value = update later

        /** report_mpls (set valid later) **/
        // hdr.report_mpls.label = update later
        hdr.report_mpls.tc = 0;
        hdr.report_mpls.bos = 0;
        hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;

        /** report_ipv4 **/
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4w4;
        hdr.report_ipv4.ihl = 4w5;
        // TODO BEFORE MERGE: confirm with DI team whether this can be zero
        hdr.report_ipv4.dscp = 0;
        hdr.report_ipv4.ecn = 2w0;
        // hdr.report_ipv4.total_len = update later
        // hdr.report_ipv4.identification = update later
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.report_ipv4.protocol = PROTO_UDP;
        // hdr.report_ipv4.hdr_checksum = update later
        // hdr.report_ipv4.src_addr = update later
        // hdr.report_ipv4.dst_addr = update later

        /** report_udp **/
        hdr.report_udp.setValid();
        hdr.report_udp.sport = 0;
        // hdr.report_udp.dport = update later
        // hdr.report_udp.len = update later
        // hdr.report_udp.checksum = update never!

        /** report_fixed_header **/
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 0;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        // hdr.report_fixed_header.d = update later
        // hdr.report_fixed_header.q = update later
        // hdr.report_fixed_header.f = update later
        hdr.report_fixed_header.rsvd = 0;
        // hdr.report_fixed_header.hw_id = update later
        // hdr.report_fixed_header.seq_no = update later

        /** common_report_header **/
        hdr.common_report_header.setValid();
        // hdr.common_report_header.switch_id = update later
    }

    @hidden
    action set_common_int_drop_headers() {
        fabric_md.int_report_md.setValid();
        fabric_md.int_report_md.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.int_report_md.report_type = INT_REPORT_TYPE_DROP;
        fabric_md.int_report_md.mirror_type = FabricMirrorType_t.INVALID;

        /** drop_report_header **/
        hdr.drop_report_header.setValid();
        // transition set_common_int_headers;
        set_common_int_headers();
    }

    @hidden
    action parse_int_deflected_drop() {
        fabric_md.int_report_md.bmd_type = BridgedMdType_t.DEFLECTED;
        fabric_md.int_report_md.encap_presence = fabric_md.bridged.base.encap_presence;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;

        /** drop_report_header **/
        hdr.drop_report_header.drop_reason = IntDropReason_t.DROP_REASON_TRAFFIC_MANAGER;
        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.bridged.base.ig_port;
        hdr.common_report_header.eg_port = fabric_md.bridged.int_bmd.egress_port;
        hdr.common_report_header.queue_id = fabric_md.bridged.int_bmd.queue_id;

        // transition set_common_int_drop_headers;
        set_common_int_drop_headers();
    }

    @hidden
    action parse_int_ingress_drop() {
        fabric_md.int_report_md.bmd_type = BridgedMdType_t.INT_INGRESS_DROP;
        fabric_md.int_report_md.encap_presence = fabric_md.bridged.base.encap_presence;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;

        /** drop_report_header **/
        hdr.drop_report_header.drop_reason = fabric_md.bridged.int_bmd.drop_reason;
        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.bridged.base.ig_port;
        hdr.common_report_header.eg_port = 0;
        hdr.common_report_header.queue_id = 0;

        // transition set_common_int_drop_headers;
        set_common_int_drop_headers();
    }

    @hidden
    action parse_int_report_mirror() {
        fabric_md.bridged.bmd_type = fabric_md.int_report_md.bmd_type;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.bridged.base.mpls_label = 0; // do not push an MPLS label
        #ifdef WITH_SPGW
            fabric_md.bridged.spgw.skip_spgw = true;
        #endif // WITH_SPGW

        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.int_report_md.ig_tstamp;

        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.int_report_md.ig_port;
        hdr.common_report_header.eg_port = fabric_md.int_report_md.eg_port;
        hdr.common_report_header.queue_id = fabric_md.int_report_md.queue_id;

        /** local/drop_report_header (set valid later) **/
        hdr.local_report_header.queue_occupancy = fabric_md.int_report_md.queue_occupancy;
        hdr.local_report_header.eg_tstamp = fabric_md.int_report_md.eg_tstamp;
        hdr.drop_report_header.drop_reason = fabric_md.int_report_md.drop_reason;

        // transition set_common_int_headers;
        set_common_int_headers();
    }

    @hidden
    table start_transition_select {
        key = {
            // using ternary to allow use of don't care operator.
            fabric_v1model.deflect_on_drop: ternary;
            fabric_md.bridged.bmd_type: ternary;
            fabric_v1model.int_mirror_type: ternary;
        }
        actions = {
            parse_int_deflected_drop;
            parse_int_ingress_drop;
            parse_int_report_mirror;
            @defaultonly drop;
        }
        const entries = {
            (1, _, _): parse_int_deflected_drop();
            (0, BridgedMdType_t.INT_INGRESS_DROP, _): parse_int_ingress_drop();
            (0, BridgedMdType_t.EGRESS_MIRROR, FabricMirrorType_t.INT_REPORT): parse_int_report_mirror();
        }
        const default_action = drop();
    }

    @hidden
    action strip_vlan() {
        hdr_v1model.ingress.vlan_tag.setInvalid();
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
        hdr_v1model.ingress.inner_vlan.setInvalid();
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
    }

    @hidden
    action strip_mpls() {
        hdr_v1model.ingress.mpls.setInvalid();
    }

    @hidden
    action handle_ipv4() {
        fabric_md.int_ipv4_len = hdr.ipv4.total_len;
    }

    @hidden
    action strip_ipv4_udp_gtpu() {
        // hdr.ipv4 = hdr_v1model.ingress.inner_ipv4;
        // hdr.udp = hdr_v1model.ingress.inner_udp;
        // hdr.tcp = hdr_v1model.ingress.inner_tcp;
        // hdr.icmp = hdr_v1model.ingress.inner_icmp;

        hdr_v1model.ingress.gtpu.setInvalid();
        hdr_v1model.ingress.ipv4.setInvalid();
        // hdr_v1model.ingress.inner_ipv4.setInvalid();
        hdr_v1model.ingress.inner_udp.setInvalid();
        hdr_v1model.ingress.inner_tcp.setInvalid();
        hdr_v1model.ingress.inner_icmp.setInvalid();

    }

    @hidden
    action strip_ipv4_udp_gtpu_psc() {
        hdr_v1model.ingress.ipv4.setInvalid();
        hdr_v1model.ingress.gtpu.setInvalid();
        hdr_v1model.ingress.gtpu_options.setInvalid();
        hdr_v1model.ingress.gtpu_ext_psc.setInvalid();
        // hdr_v1model.ingress.inner_ipv4.setInvalid();
        hdr_v1model.ingress.inner_udp.setInvalid();
        hdr_v1model.ingress.inner_tcp.setInvalid();
        hdr_v1model.ingress.inner_icmp.setInvalid();

    }

    @hidden
    table state_parse_eth_hdr {
        key = {
            // hdr.eth_type.isValid(): ternary;
            hdr_v1model.ingress.eth_type.value: ternary;
            fabric_md.int_report_md.encap_presence: ternary;
        }
        actions = {
            strip_vlan;
            strip_mpls;
            handle_ipv4;
            strip_ipv4_udp_gtpu;
            @defaultonly nop;
        }
        const entries = {
            (ETHERTYPE_VLAN &&& 0xEFFF, _): strip_vlan();
            (ETHERTYPE_MPLS, _): strip_mpls();
            (ETHERTYPE_IPV4, EncapPresence.NONE): handle_ipv4();
            (ETHERTYPE_IPV4, EncapPresence.GTPU_ONLY): strip_ipv4_udp_gtpu;
        }
        const default_action = nop();
    }

    apply {
        // state start
        start_transition_select.apply();

        state_parse_eth_hdr.apply();

        hdr_v1model.egress = hdr;
        fabric_v1model.egress = fabric_md;
    }
}

control IntEgress (
    // inout egress_headers_t hdr,
    inout v1model_header_t hdr_v1model,
    inout fabric_v1model_metadata_t fabric_v1model,
    inout standard_metadata_t standard_md
    // in    egress_intrinsic_metadata_t eg_intr_md,
    // in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    // inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
    ) {

    egress_headers_t hdr = hdr_v1model.egress;
    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;
    FlowReportFilter() flow_report_filter;
    DropReportFilter() drop_report_filter;
    IntEgressParserEmulator() parser_emulator;
    queue_report_filter_index_t queue_report_filter_index;

    direct_counter(CounterType.packets_and_bytes) report_counter;
    direct_counter(CounterType.packets_and_bytes) int_metadata_counter;

    QueueId_t egress_qid = 0; // bmv2 specific. Only one queue present.
    bool check_quota_and_report = false;
    queue_report_filter_index_t quota = 0;
    bit<1> drop_ctl = 0;

    // @hidden
    // Random<bit<16>>() ip_id_gen;
    @hidden
    register<bit<32>>(1024) seq_number;
    // RegisterAction<bit<32>, bit<6>, bit<32>>(seq_number) get_seq_number = {
    //     void apply(inout bit<32> reg, out bit<32> rv) {
    //         reg = reg + 1;
    //         rv = reg;
    //     }
    // };

    @hidden
    action get_seq_number (in bit<32> seq_number_idx, out bit<32> result) {
        bit<32> reg = 0;
        seq_number.read(reg, seq_number_idx);
        reg = reg + 1;
        result = reg;
        seq_number.write(seq_number_idx, reg);
    }

    // Register<queue_report_quota_t, queue_report_filter_index_t>(1 << QUEUE_REPORT_FILTER_WIDTH, DEFAULT_QUEUE_REPORT_QUOTA) queue_report_quota;
    register<queue_report_quota_t>(1 << QUEUE_REPORT_FILTER_WIDTH) queue_report_quota;
    // @hidden
    // action _initialize_register(bit<32> idx) {
    //     // Emulate the TNA RegisterAction behavior by initializing the register to a potential non-zero value.
    //     queue_report_quota.write(idx, DEFAULT_QUEUE_REPORT_QUOTA);
    // }
    // RegisterAction<queue_report_quota_t, queue_report_filter_index_t, bool>(queue_report_quota) check_quota_and_report = {
    //     void apply(inout queue_report_quota_t quota, out bool report) {
    //         if (quota > 0) {
    //             quota = quota - 1;
    //             report = true;
    //         } else {
    //             report = false;
    //         }
    //     }
    // };

    // RegisterAction<queue_report_quota_t, queue_report_filter_index_t, bool>(queue_report_quota) reset_report_quota = {
    //     void apply(inout queue_report_quota_t quota, out bool report) {
    //         quota = DEFAULT_QUEUE_REPORT_QUOTA;
    //         report = false;
    //     }
    // };

    action check_quota() {
        // fabric_md.int_md.queue_report = check_quota_and_report.execute(queue_report_filter_index);
        // The logic is performed in apply{} section.
        check_quota_and_report = true;
    }

    action reset_quota() {
        // fabric_md.int_md.queue_report = reset_report_quota.execute(queue_report_filter_index);
        queue_report_quota.write((bit<32>)queue_report_filter_index, DEFAULT_QUEUE_REPORT_QUOTA);
    }

    table queue_latency_thresholds {
        key = {
            // In SD-Fabric, we use the same traffic class<>queue ID mapping for all ports.
            // Hence, there's no need to match on the egress port, we can use the same
            // per-queue thresholds for all ports.
            // eg_intr_md.egress_qid: exact @name("egress_qid");
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
        // Constant fields are initialized in int_mirror_parser.p4.
        // hdr.report_ipv4.identification = ip_id_gen.get();
        random(hdr.report_ipv4.identification, 0, 0xffff);

        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;
        hdr.report_udp.dport = mon_port;
        // hdr.report_fixed_header.seq_no = get_seq_number.execute(hdr.report_fixed_header.hw_id);
        get_seq_number((bit<32>)hdr.report_fixed_header.hw_id, hdr.report_fixed_header.seq_no);
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
        // eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INVALID;

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
        // eg_dprsr_md.mirror_type = (bit<3>)FabricMirrorType_t.INT_REPORT;
        fabric_v1model.int_mirror_type = (bit<3>)FabricMirrorType_t.INT_REPORT;
        fabric_md.int_report_md.bmd_type = BridgedMdType_t.EGRESS_MIRROR;
        fabric_md.int_report_md.mirror_type = FabricMirrorType_t.INT_REPORT;
        fabric_md.int_report_md.report_type = fabric_md.bridged.int_bmd.report_type;
        fabric_md.int_report_md.ig_port = fabric_md.bridged.base.ig_port;
        // fabric_md.int_report_md.eg_port = eg_intr_md.egress_port;
        fabric_md.int_report_md.eg_port = standard_md.egress_spec;
        // fabric_md.int_report_md.queue_id = eg_intr_md.egress_qid;
        fabric_md.int_report_md.queue_id = egress_qid;
        // fabric_md.int_report_md.queue_occupancy = eg_intr_md.enq_qdepth;
        fabric_md.int_report_md.queue_occupancy = standard_md.deq_qdepth;
        fabric_md.int_report_md.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        // fabric_md.int_report_md.eg_tstamp = eg_prsr_md.global_tstamp[31:0];
        fabric_md.int_report_md.eg_tstamp = standard_md.egress_global_timestamp[31:0];
        fabric_md.int_report_md.ip_eth_type = fabric_md.bridged.base.ip_eth_type;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;
        // fabric_md.int_report_md.encap_presence set by the parser

        fabric_md.int_report_md.report_type = report_type;
        int_metadata_counter.count();
    }

    // Initializes the INT mirror metadata.
    @hidden
    table int_metadata {
        key = {
            fabric_md.bridged.int_bmd.report_type: exact @name("int_report_type");
            // eg_dprsr_md.drop_ctl: exact @name("drop_ctl");
            // drop_ctl not available as intrinsic metadata.
            drop_ctl: exact @name("drop_ctl"); //FIXME declare drop_ctl as custom metadata
            fabric_md.int_md.queue_report: exact @name("queue_report");
        }
        actions = {
            init_int_metadata;
            @defaultonly nop();
        }
        const default_action = nop();
        const entries = {
            (INT_REPORT_TYPE_FLOW, 0, false): init_int_metadata(INT_REPORT_TYPE_FLOW);
            (INT_REPORT_TYPE_FLOW, 0, true): init_int_metadata(INT_REPORT_TYPE_FLOW|INT_REPORT_TYPE_QUEUE);
            (INT_REPORT_TYPE_FLOW, 1, false): init_int_metadata(INT_REPORT_TYPE_DROP);
            (INT_REPORT_TYPE_FLOW, 1, true): init_int_metadata(INT_REPORT_TYPE_DROP);
            // Packets which are not tracked by the watchlist table
            (INT_REPORT_TYPE_NO_REPORT, 0, true): init_int_metadata(INT_REPORT_TYPE_QUEUE);
            (INT_REPORT_TYPE_NO_REPORT, 1, true): init_int_metadata(INT_REPORT_TYPE_QUEUE);
        }

        counters = int_metadata_counter;
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
        const entries = {
            INT_IS_WIP: adjust_ip_udp_len(INT_WIP_ADJUST_IP_BYTES, INT_WIP_ADJUST_UDP_BYTES);
            INT_IS_WIP_WITH_MPLS: adjust_ip_udp_len(INT_WIP_ADJUST_IP_MPLS_BYTES, INT_WIP_ADJUST_UDP_MPLS_BYTES);
        }
    }

    apply {
        if (IS_E2E_CLONE(standard_md)) {
            // Apply emulator only on mirrored packet.
            parser_emulator.apply(hdr_v1model, fabric_v1model, standard_md);
        }
        // fabric_md.int_md.hop_latency = eg_prsr_md.global_tstamp[31:0] - fabric_md.bridged.base.ig_tstamp[31:0];
        fabric_md.int_md.hop_latency = standard_md.egress_global_timestamp[31:0] - fabric_md.bridged.base.ig_tstamp[31:0];

        // fabric_md.int_md.timestamp = eg_prsr_md.global_tstamp;
        fabric_md.int_md.timestamp = standard_md.egress_global_timestamp;
        // Here we use the lower 7-bit of port number with qid as the register index
        // Only 7-bit because registers are independent between pipes.
        // queue_report_filter_index = eg_intr_md.egress_port[6:0] ++ eg_intr_md.egress_qid;
        queue_report_filter_index = standard_md.egress_spec[6:0] ++ egress_qid; //FIXME in case of bmv2 this is always 0. is it ok?
        // _initialize_register((bit<32>)queue_report_filter_index);

        // Check the queue alert before the config table since we need to check the
        // latency which is not quantized.
        queue_latency_thresholds.apply();
        // In v1model, we're not allowed to have an apply{} section within an action,
        // so the conditional that was present in RegisterAction is now here.
        if (check_quota_and_report) {
            if (quota > 0) {
                quota = quota - 1;
                fabric_md.int_md.queue_report = true;
            } else {
                fabric_md.int_md.queue_report = false;
            }
        }

        config.apply();
        // hdr.report_fixed_header.hw_id = 4w0 ++ eg_intr_md.egress_port[8:7];
        hdr.report_fixed_header.hw_id = 4w0 ++ standard_md.egress_spec[8:7];

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
        // drop_report_filter.apply(hdr, fabric_md, eg_dprsr_md);
        drop_report_filter.apply(hdr, fabric_md, standard_md);

        if (fabric_md.int_report_md.isValid()) {
            // Packet is mirrored (egress or deflected) or an ingress drop.
            report.apply();
        } else {
            // Regular packet. Initialize INT mirror metadata but let
            // filter decide whether to generate a mirror or not.
            if (int_metadata.apply().hit) {
                // flow_report_filter.apply(hdr, fabric_md, eg_intr_md, eg_prsr_md, eg_dprsr_md);
                flow_report_filter.apply(hdr, fabric_v1model, standard_md);
            }
        }

        adjust_int_report_hdr_length.apply();
        fabric_v1model.egress = fabric_md;
    }
}
#endif
