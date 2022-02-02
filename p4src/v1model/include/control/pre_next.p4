// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include <core.p4>

#include "v1model/include/header_v1model.p4"

control PreNext(inout ingress_headers_t hdr,
                inout fabric_ingress_metadata_t fabric_md) {

    /*
     * Next MPLS table.
     * Set the MPLS label based on the next ID.
     */
    direct_counter(CounterType.packets_and_bytes) next_mpls_counter;

    action set_mpls_label(mpls_label_t label) {
        fabric_md.bridged.base.mpls_label = label;
        next_mpls_counter.count();
    }

    table next_mpls {
        key = {
            fabric_md.next_id: exact @name("next_id");
        }
        actions = {
            set_mpls_label;
            @defaultonly nop;
        }
        const default_action = nop();
        counters = next_mpls_counter;
        size = NEXT_MPLS_TABLE_SIZE;
    }

    /*
     * Next VLAN table.
     * Modify VLAN ID based on next ID.
     */
    direct_counter(CounterType.packets_and_bytes) next_vlan_counter;

    action set_vlan(vlan_id_t vlan_id) {
        fabric_md.bridged.base.vlan_id = vlan_id;
        next_vlan_counter.count();
    }

#ifdef WITH_DOUBLE_VLAN_TERMINATION
    action set_double_vlan(vlan_id_t outer_vlan_id, vlan_id_t inner_vlan_id) {
        set_vlan(outer_vlan_id);
        fabric_md.bridged.base.push_double_vlan = true;
        fabric_md.bridged.base.inner_vlan_id = inner_vlan_id;
    }
#endif // WITH_DOUBLE_VLAN_TERMINATION

    table next_vlan {
        key = {
            fabric_md.next_id: exact @name("next_id");
        }
        actions = {
            set_vlan;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
            set_double_vlan;
#endif // WITH_DOUBLE_VLAN_TERMINATION
            @defaultonly nop;
        }
        const default_action = nop();
        counters = next_vlan_counter;
        size = NEXT_VLAN_TABLE_SIZE;
    }

    apply {
        next_mpls.apply();
        next_vlan.apply();
    }
}
