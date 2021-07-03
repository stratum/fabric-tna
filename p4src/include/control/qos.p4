// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>
#include <tna.p4>

#include "../header.p4"

// Check Stratum's chassis_config for other queue IDs.
const qid_t BEST_EFFORT_QUEUE = 0;

control QoS (in ingress_headers_t hdr,
             in fabric_ingress_metadata_t fabric_md,
             inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) tc_counter;

    action set_queue(qid_t qid) {
        ig_tm_md.qid = qid;
        tc_counter.count();
    }

    table traffic_classes {
        key = {
            fabric_md.slice_id: exact @name("slice_id");
            fabric_md.tc:       exact @name("tc");
        }
        actions = {
            set_queue;
        }
        counters = tc_counter;
        const default_action = set_queue(BEST_EFFORT_QUEUE);
        size = QUEUES_TABLE_SIZE;
    }

    apply {
        traffic_classes.apply();
    }
}
