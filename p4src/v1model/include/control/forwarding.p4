// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>

#include "shared/define.p4"
#include "shared/header.p4"


control Forwarding (inout ingress_headers_t hdr,
                    inout fabric_ingress_metadata_t fabric_md) {


    @hidden
    action set_next_id(next_id_t next_id) {
        fabric_md.next_id = next_id;
    }

    /*
     * Bridging Table.
     */
    direct_counter(CounterType.packets_and_bytes) bridging_counter;

    action set_next_id_bridging(next_id_t next_id) {
        set_next_id(next_id);
        bridging_counter.count();
    }

    // FIXME: using ternary for eth_dst prevents our ability to scale in
    //  bridging heavy environments. Do we really need ternary? Can we come up
    //  with a multi-table approach?
    table bridging {
        key = {
            fabric_md.bridged.base.vlan_id : exact @name("vlan_id");
            hdr.ethernet.dst_addr          : ternary @name("eth_dst");
        }
        actions = {
            set_next_id_bridging;
            @defaultonly nop;
        }
        const default_action = nop();
        counters = bridging_counter;
        size = BRIDGING_TABLE_SIZE;
    }

    /*
     * MPLS Table.
     */
    direct_counter(CounterType.packets_and_bytes) mpls_counter;

    action pop_mpls_and_next(next_id_t next_id) {
        hdr.mpls.setInvalid();
        hdr.eth_type.value = fabric_md.bridged.base.ip_eth_type;
        fabric_md.bridged.base.mpls_label = 0;
        set_next_id(next_id);
        mpls_counter.count();
    }

    table mpls {
        key = {
            fabric_md.bridged.base.mpls_label : exact @name("mpls_label");
        }
        actions = {
            pop_mpls_and_next;
            @defaultonly nop;
        }
        const default_action = nop();
        counters = mpls_counter;
        size = MPLS_TABLE_SIZE;
    }

    /*
     * IPv4 Routing Table.
     */

    action set_next_id_routing_v4(next_id_t next_id) {
        set_next_id(next_id);
    }

    action nop_routing_v4() {
        // no-op
    }

    table routing_v4 {
        key = {
            fabric_md.routing_ipv4_dst: lpm @name("ipv4_dst");
        }
        actions = {
            set_next_id_routing_v4;
            nop_routing_v4;
            @defaultonly nop;
        }
        default_action = nop();
        size = ROUTING_V4_TABLE_SIZE;
    }

    /*
     * IPv6 Routing Table.
     */

    action set_next_id_routing_v6(next_id_t next_id) {
        set_next_id(next_id);
    }

    table routing_v6 {
        key = {
            hdr.ipv6.dst_addr: lpm @name("ipv6_dst");
        }
        actions = {
            set_next_id_routing_v6;
            @defaultonly nop;
        }
        default_action = nop();
        size = ROUTING_V6_TABLE_SIZE;
    }

    apply {
        if (hdr.ethernet.isValid() &&
                fabric_md.bridged.base.fwd_type == FWD_BRIDGING) {
            bridging.apply();
        } else if (hdr.mpls.isValid() &&
                       fabric_md.bridged.base.fwd_type == FWD_MPLS) {
            mpls.apply();
        } else if (fabric_md.lkp.is_ipv4 &&
                       (fabric_md.bridged.base.fwd_type == FWD_IPV4_UNICAST ||
                            fabric_md.bridged.base.fwd_type == FWD_IPV4_MULTICAST)) {
            routing_v4.apply();
        } else if (hdr.ipv6.isValid() &&
                       fabric_md.bridged.base.fwd_type == FWD_IPV6_UNICAST) {
            routing_v6.apply();
        }
    }
}
