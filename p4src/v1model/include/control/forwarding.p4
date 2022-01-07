// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"


control Forwarding (inout ingress_headers_t hdr,
                    inout fabric_v1model_metadata_t fabric_v1model,
                    inout standard_metadata_t standard_md) {

    fabric_ingress_metadata_t fabric_md = fabric_v1model.ingress;

#ifdef WITH_INT
    action set_int_drop_reason(bit<8> drop_reason) {
        fabric_md.bridged.int_bmd.drop_reason = (IntDropReason_t)drop_reason;
    }
#endif // WITH_INT

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
            hdr.ethernet.dst_addr     : ternary @name("eth_dst");
        }
        actions = {
            set_next_id_bridging;
#ifdef WITH_INT
            @defaultonly set_int_drop_reason;
#else
            @defaultonly nop;
#endif // WITH_INT
        }
#ifdef WITH_INT
        const default_action = set_int_drop_reason(IntDropReason_t.DROP_REASON_BRIDGING_MISS);
#else
        const default_action = nop();
#endif // WITH_INT
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
#ifdef WITH_INT
            @defaultonly set_int_drop_reason;
#else
            @defaultonly nop;
#endif // WITH_INT
        }
#ifdef WITH_INT
        const default_action = set_int_drop_reason(IntDropReason_t.DROP_REASON_MPLS_MISS);
#else
        const default_action = nop();
#endif // WITH_INT
        counters = mpls_counter;
        size = MPLS_TABLE_SIZE;
    }

    /*
     * IPv4 Routing Table.
     */
    direct_counter(CounterType.packets_and_bytes) routing_v4_counter;

    action set_next_id_routing_v4(next_id_t next_id) {
        set_next_id(next_id);
        routing_v4_counter.count();
    }

    action nop_routing_v4() {
        // no-op
        routing_v4_counter.count();
    }

    action drop_routing_v4() {
        fabric_md.skip_next = true;
        routing_v4_counter.count();
        fabric_v1model.drop_ctl = 1;
    }

    table routing_v4 {
        key = {
            fabric_md.routing_ipv4_dst: lpm @name("ipv4_dst");
        }
        actions = {
            set_next_id_routing_v4;
            nop_routing_v4;
            drop_routing_v4;
#ifdef WITH_INT
            @defaultonly set_int_drop_reason;
#else
            @defaultonly nop;
#endif // WITH_INT
        }
#ifdef WITH_INT
        default_action = set_int_drop_reason(IntDropReason_t.DROP_REASON_ROUTING_V4_MISS);
#else
        default_action = nop();
#endif // WITH_INT
        counters = routing_v4_counter;
        size = ROUTING_V4_TABLE_SIZE;
    }

    /*
     * IPv6 Routing Table.
     */
    direct_counter(CounterType.packets_and_bytes) routing_v6_counter;

    action set_next_id_routing_v6(next_id_t next_id) {
        set_next_id(next_id);
        routing_v6_counter.count();
    }

    action drop_routing_v6() {
        fabric_md.skip_next = true;
        routing_v6_counter.count();
        fabric_v1model.drop_ctl = 1;
    }

    table routing_v6 {
        key = {
            hdr.ipv6.dst_addr: lpm @name("ipv6_dst");
        }
        actions = {
            set_next_id_routing_v6;
            drop_routing_v6;
#ifdef WITH_INT
            @defaultonly set_int_drop_reason;
#else
            @defaultonly nop;
#endif // WITH_INT
        }
#ifdef WITH_INT
        default_action = set_int_drop_reason(IntDropReason_t.DROP_REASON_ROUTING_V6_MISS);
#else
        default_action = nop();
#endif // WITH_INT
        counters = routing_v6_counter;
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

        fabric_v1model.ingress = fabric_md;
    }
}
