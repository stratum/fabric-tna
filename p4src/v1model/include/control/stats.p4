// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "shared/header.p4"

// The control plane should never use this flow ID.
// Used to force initialization of stats_flow_id metadata.
const bit<STATS_FLOW_ID_WIDTH> UNSET_FLOW_ID = 0;

control StatsIngress (in lookup_metadata_t lkp,
                      in PortId_t ig_port,
                      out bit<STATS_FLOW_ID_WIDTH> stats_flow_id) {

    direct_counter(CounterType.packets_and_bytes) flow_counter;

    action count(bit<STATS_FLOW_ID_WIDTH> flow_id) {
        stats_flow_id = flow_id;
        flow_counter.count();
    }

    table flows {
        key = {
            lkp.ipv4_src : ternary @name("ipv4_src");
            lkp.ipv4_dst : ternary @name("ipv4_dst");
            lkp.ip_proto : ternary @name("ip_proto");
            lkp.l4_sport : ternary @name("l4_sport");
            lkp.l4_dport : ternary @name("l4_dport");
            ig_port      : exact @name("ig_port");
        }
        actions = {
            count;
        }
        const default_action = count(UNSET_FLOW_ID);
        const size = 1 << STATS_FLOW_ID_WIDTH;
        counters = flow_counter;
    }

    apply {
        flows.apply();
    }
}

control StatsEgress (in bit<STATS_FLOW_ID_WIDTH> stats_flow_id,
                     in PortId_t eg_port,
                     in BridgedMdType_t bmd_type) {

    direct_counter(CounterType.packets_and_bytes) flow_counter;

    action count() {
        flow_counter.count();
    }

    table flows {
        key = {
            stats_flow_id : exact @name("stats_flow_id");
            eg_port       : exact @name("eg_port");
        }
        actions = {
            count;
        }
        const default_action = count;
        const size = 1 << STATS_FLOW_ID_WIDTH;
        counters = flow_counter;
    }

    apply {
        if (bmd_type == BridgedMdType_t.INGRESS_TO_EGRESS) {
            // Do not update stats for INT reports and other mirrored packets.
            // stats_flow_id will be valid only for bridged packets.
            flows.apply();
        }
    }
}
