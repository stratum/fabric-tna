// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>

#include "shared/header.p4"

// ACL-like classification, maps lookup metadata to slice_id and tc. For UE
// traffic, the classification provided by the SPGW tables takes precendence.
// To apply the same slicing and QoS treatment end-to-end, we use the IPv4 DSCP
// field to piggyback slice_id and tc (see EgressDscpRewriter). This is
// especially important for UE traffic, where classification based on PDRs can
// only happen at the ingress leaf switch (implementing the UPF function).
// As such, for traffic coming from selected ports, we allow trusting the
// slice_id and tc values carried in the dscp.
control IngressSliceTcClassifier (inout    ingress_headers_t hdr,
                                  inout    standard_metadata_t standard_md,
                                  inout fabric_ingress_metadata_t fabric_md) {

    direct_counter(CounterType.packets) classifier_stats;

    action set_slice_id_tc(slice_id_t slice_id, tc_t tc) {
        fabric_md.slice_id = slice_id;
        fabric_md.tc = tc;
        classifier_stats.count();
    }

    // Should be used only for infrastructure ports (leaf-leaf, or leaf-spine),
    // or ports facing servers that implement early classification based on the
    // SDFAB DSCP encoding (slice_id++tc).
    action trust_dscp() {
        fabric_md.slice_id = hdr.ipv4.dscp[SLICE_ID_WIDTH+TC_WIDTH-1:TC_WIDTH];
        fabric_md.tc = hdr.ipv4.dscp[TC_WIDTH-1:0];
        classifier_stats.count();
    }

    table classifier {
        key = {
            standard_md.ingress_port : ternary @name("ig_port");
            fabric_md.lkp.ipv4_src   : ternary @name("ipv4_src");
            fabric_md.lkp.ipv4_dst   : ternary @name("ipv4_dst");
            fabric_md.lkp.ip_proto   : ternary @name("ip_proto");
            fabric_md.lkp.l4_sport   : ternary @name("l4_sport");
            fabric_md.lkp.l4_dport   : ternary @name("l4_dport");
        }
        actions = {
            set_slice_id_tc;
            trust_dscp;
        }
        const default_action = set_slice_id_tc(DEFAULT_SLICE_ID, DEFAULT_TC);
        counters = classifier_stats;
        size = QOS_CLASSIFIER_TABLE_SIZE;
    }

    apply {
        classifier.apply();
    }
}

// Provides metering and mapping to queues based on slice_id and tc. Should be
// applied after any other block writing slice_id and tc.
control IngressQos (inout fabric_ingress_metadata_t fabric_md,
                    inout standard_metadata_t standard_md){
                    //inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                    //inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // From now on we use the concatenated slice_id++tc to aid the compiler in
    // optimizing resource allocation.

    @hidden
    action use_spgw() {
        fabric_md.bridged.base.slice_tc = fabric_md.spgw_slice_id++fabric_md.spgw_tc;
    }

    @hidden
    action use_default() {
        fabric_md.bridged.base.slice_tc = fabric_md.slice_id++fabric_md.tc;
    }

    // Use SPGW classification if the packet was terminated by this switch.
    @hidden
    table set_slice_tc {
        key = { fabric_md.is_spgw_hit: exact; }
        actions = { use_spgw; use_default; }
        const size = 2;
        const entries = {
            true: use_spgw;
            false: use_default;
        }
    }

    // One meter per tc per slice. Consider using optional argument
    // adjust_byte_count to account only for user-generated bytes, i.e., exclude
    // VLAN, MPLS, GTP-U.
    meter(1 << SLICE_TC_WIDTH, MeterType.bytes) slice_tc_meter;

    direct_counter(CounterType.packets) queues_stats;

    action set_queue(QueueId_t qid) {
        //ig_tm_md.qid = qid; //Useless for Bmv2.
        queues_stats.count();
    }

    // For policing.
    action meter_drop() {
        mark_to_drop(standard_md);
        queues_stats.count();
    }

    table queues {
        key = {
            // FIXME: match on slice_id and tc instead of concatenated slice_tc
            //  Using bit-slicing to define two match fields causes a Stratum
            //  runtime bug with the context JSON produced with SDE 9.3.0:
            //  "Could not find field fabric_md.bridged.base_slice_tc in match
            //  spec." Try removing workaround with future SDE releases.
            // fabric_md.bridged.base.slice_tc[SLICE_ID_WIDTH+TC_WIDTH-1:TC_WIDTH]: exact @name("slice_id");
            // fabric_md.bridged.base.slice_tc[TC_WIDTH-1:0]: exact @name("tc");
            fabric_md.bridged.base.slice_tc: exact   @name("slice_tc");
            fabric_md.packet_color:          ternary @name("color"); // 0=GREEN, 1=YELLOW, 2=RED
        }
        actions = {
            set_queue;
            meter_drop;
        }
        const default_action = set_queue(QUEUE_ID_BEST_EFFORT);
        counters = queues_stats;
        // Two times the number of tcs for all slices, because we might need to
        // match on different colors for the same slice and tc.
        size = 1 << (SLICE_TC_WIDTH + 1);
    }

    apply {
        // Meter index should be 0 for all packets with default slice_id and tc.
        set_slice_tc.apply();
        slice_tc_meter.execute_meter((bit<32>) fabric_md.bridged.base.slice_tc, fabric_md.packet_color);
        queues.apply();
    }
}

// Allows per-egress port rewriting of the outermost IPv4 DSCP field to
// piggyback slice_id and tc across the fabric.
control EgressDscpRewriter (inout fabric_ingress_metadata_t fabric_md,
                            inout standard_metadata_t standard_md,
                            inout ingress_headers_t hdr) {

    bit<6> tmp_dscp = fabric_md.bridged.base.slice_tc;

    action rewrite() {
        // Do nothing, tmp_dscp is already initialized.
    }

    // Sets the DSCP field to zero. Should be used for edge ports facing devices
    // that do not support the SDFAB DSCP encoding.
    action clear() {
        tmp_dscp = 0;
    }

    table rewriter {
        key = {
            standard_md.egress_port : exact @name("eg_port");
        }
        actions = {
            rewrite;
            clear;
            @defaultonly nop;
        }
        const default_action = nop;
        size = DSCP_REWRITER_TABLE_SIZE;
    }

    apply {
        if (rewriter.apply().hit) {
            if (hdr.ipv4.isValid()) {
                hdr.ipv4.dscp = tmp_dscp;
            }
        }
    }
}