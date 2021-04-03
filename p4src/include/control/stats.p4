// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "../header.p4"

control Stats (in acl_lookup_t acl_lkp,
               in PortId_t port) {

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) flow_counter;

    action count() {
        flow_counter.count();
    }

    table flows {
        key = {
            acl_lkp.ipv4_src : ternary @name("ipv4_src");
            acl_lkp.ipv4_dst : ternary @name("ipv4_dst");
            acl_lkp.ip_proto : ternary @name("ip_proto");
            acl_lkp.l4_sport : ternary @name("l4_sport");
            acl_lkp.l4_dport : ternary @name("l4_dport");
            port             : ternary @name("port");
        }
        actions = {
            count;
        }
        const default_action = count;
        const size = STATS_TABLE_SIZE;
        counters = flow_counter;
    }

    apply {
        flows.apply();
    }
}
