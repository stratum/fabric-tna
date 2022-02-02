// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include <core.p4>
#include <tna.p4>

#include "shared/define.p4"
#include "shared/header.p4"


control Forwarding (inout ingress_headers_t hdr,
                    inout fabric_ingress_metadata_t fabric_md,
                    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

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
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) bridging_counter;

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
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) mpls_counter;

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
#ifdef WITH_DEBUG
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) routing_v4_counter;
#endif // WITH_DEBUG

    action set_next_id_routing_v4(next_id_t next_id) {
        set_next_id(next_id);
#ifdef WITH_DEBUG
        routing_v4_counter.count();
#endif // WITH_DEBUG
    }

    action nop_routing_v4() {
        // no-op
#ifdef WITH_DEBUG
        routing_v4_counter.count();
#endif // WITH_DEBUG
    }

    action drop_routing_v4() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        set_int_drop_reason(IntDropReason_t.DROP_REASON_ROUTING_V4_DROP);
#endif // WITH_INT
#ifdef WITH_DEBUG
        routing_v4_counter.count();
#endif // WITH_DEBUG
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
#ifdef WITH_DEBUG
        counters = routing_v4_counter;
#endif // WITH_DEBUG
        size = ROUTING_V4_TABLE_SIZE;
    }

    /*
     * IPv6 Routing Table.
     */
#ifdef WITH_DEBUG
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) routing_v6_counter;
#endif // WITH_DEBUG

    action set_next_id_routing_v6(next_id_t next_id) {
        set_next_id(next_id);
#ifdef WITH_DEBUG
        routing_v6_counter.count();
#endif // WITH_DEBUG
    }

    action drop_routing_v6() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        set_int_drop_reason(IntDropReason_t.DROP_REASON_ROUTING_V6_DROP);
#endif // WITH_INT
#ifdef WITH_DEBUG
        routing_v6_counter.count();
#endif // WITH_DEBUG
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
#ifdef WITH_DEBUG
        counters = routing_v6_counter;
#endif // WITH_DEBUG
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
