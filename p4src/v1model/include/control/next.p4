// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>

#include "v1model/include/header_v1model.p4"

control Next (inout ingress_headers_t hdr,
              //inout fabric_ingress_metadata_t fabric_md,
              inout fabric_v1model_metadata_t fabric_v1model,
              inout standard_metadata_t standard_md) {

    /*
     * General actions.
     */
     fabric_ingress_metadata_t fabric_md = fabric_v1model.ingress;

    @hidden
    action output(PortId_t port_num) {
        standard_md.egress_spec = port_num;
        fabric_md.egress_port_set = true;
    }

    @hidden
    action rewrite_smac(mac_addr_t smac) {
        hdr.ethernet.src_addr = smac;
    }

    @hidden
    action rewrite_dmac(mac_addr_t dmac) {
        hdr.ethernet.dst_addr = dmac;
    }

    @hidden
    action routing(PortId_t port_num, mac_addr_t smac, mac_addr_t dmac) {
        rewrite_smac(smac);
        rewrite_dmac(dmac);
        output(port_num);
    }

#ifdef WITH_XCONNECT
    /*
     * Cross-connect table.
     * Bidirectional forwarding for the same next id.
     */
    direct_counter(CounterType.packets_and_bytes) xconnect_counter;

    action output_xconnect(PortId_t port_num) {
        output(port_num);
        xconnect_counter.count();
    }

    action set_next_id_xconnect(next_id_t next_id) {
        fabric_md.next_id = next_id;
        xconnect_counter.count();
    }

    table xconnect {
        key = {
            standard_md.ingress_port: exact @name("ig_port");
            fabric_md.next_id       : exact @name("next_id");
        }
        actions = {
            output_xconnect;
            set_next_id_xconnect;
            @defaultonly nop;
        }
        counters = xconnect_counter;
        const default_action = nop();
        size = XCONNECT_NEXT_TABLE_SIZE;
    }
#endif // WITH_XCONNECT

#ifdef WITH_SIMPLE_NEXT
    /*
     * Simple Table.
     * Do a single egress action based on next id.
     */
    direct_counter(CounterType.packets_and_bytes) simple_counter;

    action output_simple(PortId_t port_num) {
        output(port_num);
        simple_counter.count();
    }

    action routing_simple(PortId_t port_num, mac_addr_t smac, mac_addr_t dmac) {
        routing(port_num, smac, dmac);
        simple_counter.count();
    }

    table simple {
        key = {
            fabric_md.next_id: exact @name("next_id");
        }
        actions = {
            output_simple;
            routing_simple;
            @defaultonly nop;
        }
        const default_action = nop();
        counters = simple_counter;
        size = SIMPLE_NEXT_TABLE_SIZE;
    }
#endif // WITH_SIMPLE_NEXT

#ifdef WITH_HASHED_NEXT
    /*
     * Hashed table.
     * Execute an action profile selector based on next id.
     */
    // TODO: Find a good size for Hash
    @max_group_size(HASHED_SELECTOR_MAX_GROUP_SIZE)
    action_selector(HashAlgorithm.crc16,
        HASHED_SELECTOR_MAX_GROUP_SIZE,
        32w16) hashed_profile; // Still an action_selector. This name is used to limit
                               // the usage of custom testing code between TNA and bmv2, for action_selectors.

    direct_counter(CounterType.packets_and_bytes) hashed_counter;

    action output_hashed(PortId_t port_num) {
        output(port_num);
        hashed_counter.count();
    }

    action routing_hashed(PortId_t port_num, mac_addr_t smac, mac_addr_t dmac) {
        routing(port_num, smac, dmac);
        hashed_counter.count();
    }

    table hashed {
        key = {
            fabric_md.next_id           : exact @name("next_id");
            fabric_md.ecmp_hash         : selector;
        }
        actions = {
            output_hashed;
            routing_hashed;
            @defaultonly nop;
        }
        implementation = hashed_profile;
        counters = hashed_counter;
        const default_action = nop();
        size = HASHED_NEXT_TABLE_SIZE;
    }
#endif // WITH_HASHED_NEXT

    /*
     * Multicast
     * Maps next IDs to PRE multicat group IDs.
     */
    direct_counter(CounterType.packets_and_bytes) multicast_counter;

    action set_mcast_group_id(MulticastGroupId_t group_id) {
        standard_md.mcast_grp = group_id;
        fabric_md.bridged.base.is_multicast = true;
        multicast_counter.count();
    }

    action reset_mcast_group_id() {
        standard_md.mcast_grp = 0;
        fabric_md.bridged.base.is_multicast = false;
    }

    table multicast {
        key = {
            fabric_md.next_id: exact @name("next_id");
        }
        actions = {
            set_mcast_group_id;
            @defaultonly reset_mcast_group_id;
        }
        counters = multicast_counter;
        const default_action = reset_mcast_group_id();
        size = MULTICAST_NEXT_TABLE_SIZE;
    }

    apply {
#ifdef WITH_XCONNECT
        // xconnect might set a new next_id.
        xconnect.apply();
#endif // WITH_XCONNECT
#ifdef WITH_SIMPLE_NEXT
        simple.apply();
#endif // WITH_SIMPLE_NEXT
#ifdef WITH_HASHED_NEXT
        hashed.apply();
#endif // WITH_HASHED_NEXT
        multicast.apply();

        fabric_v1model.ingress = fabric_md;
    }
}

control EgressNextControl (inout ingress_headers_t hdr,
                        //    inout fabric_egress_metadata_t fabric_md,
                           inout fabric_v1model_metadata_t fabric_v1model,
                           inout standard_metadata_t standard_md
                           ) {

    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;

    @hidden
    action pop_mpls_if_present() {
        hdr.mpls.setInvalid();
        // Assuming there's an IP header after the MPLS one.
        hdr.eth_type.value = fabric_md.bridged.base.ip_eth_type;
    }

    @hidden
    action set_mpls() {
        hdr.mpls.setValid();
        hdr.mpls.label = fabric_md.bridged.base.mpls_label;
        hdr.mpls.tc = 3w0;
        hdr.mpls.bos = 1w1; // BOS = TRUE
        hdr.mpls.ttl = fabric_md.bridged.base.mpls_ttl; // Will be decremented after push.
        hdr.eth_type.value = ETHERTYPE_MPLS;
    }

    @hidden
    action push_outer_vlan() {
        // If VLAN is already valid, we overwrite it with a potentially new VLAN
        // ID, and same CFI, PRI, and eth_type values found in ingress.
        hdr.vlan_tag.setValid();
        // hdr.vlan_tag.cfi = fabric_md.bridged.base.vlan_cfi;
        // hdr.vlan_tag.pri = fabric_md.bridged.base.vlan_pri;
        hdr.vlan_tag.eth_type = ETHERTYPE_VLAN;
        hdr.vlan_tag.vlan_id = fabric_md.bridged.base.vlan_id;
    }

#ifdef WITH_DOUBLE_VLAN_TERMINATION
    @hidden
    action push_inner_vlan() {
        // Push inner VLAN TAG, rewriting correclty the outer vlan eth_type
        hdr.inner_vlan_tag.setValid();
        // hdr.inner_vlan_tag.cfi = fabric_md.bridged.base.inner_vlan_cfi;
        // hdr.inner_vlan_tag.pri = fabric_md.bridged.base.inner_vlan_pri;
        hdr.inner_vlan_tag.vlan_id = fabric_md.bridged.base.inner_vlan_id;
        hdr.inner_vlan_tag.eth_type = ETHERTYPE_VLAN;
    }
#endif // WITH_DOUBLE_VLAN_TERMINATION

    /*
     * Egress VLAN Table.
     * Pushes or Pops the VLAN tag if the pair egress port and VLAN ID is matched.
     * Instead, it drops the packets on miss.
     */
    direct_counter(CounterType.packets_and_bytes) egress_vlan_counter;

    action push_vlan() {
        push_outer_vlan();
        egress_vlan_counter.count();
    }

    action pop_vlan() {
        hdr.vlan_tag.setInvalid();
        egress_vlan_counter.count();
    }

    action drop() {
        fabric_v1model.drop_ctl = 1;
        egress_vlan_counter.count();
#ifdef WITH_INT
        fabric_md.int_report_md.drop_reason = IntDropReason_t.DROP_REASON_EGRESS_NEXT_MISS;
#endif // WITH_INT
    }

    table egress_vlan {
        key = {
            fabric_md.bridged.base.vlan_id : exact @name("vlan_id");
            standard_md.egress_port        : exact @name("eg_port");
        }
        actions = {
            push_vlan;
            pop_vlan;
            @defaultonly drop;
        }
        const default_action = drop();
        counters = egress_vlan_counter;
        size = EGRESS_VLAN_TABLE_SIZE;
    }

    apply {
        if (fabric_md.bridged.base.is_multicast
             && fabric_md.bridged.base.ig_port == standard_md.egress_port) {
            fabric_v1model.drop_ctl = 1;
        }

        if (fabric_md.bridged.base.mpls_label == 0) {
            if (hdr.mpls.isValid()) pop_mpls_if_present();
        } else {
            set_mpls();
        }

#ifdef WITH_DOUBLE_VLAN_TERMINATION
        if (fabric_md.bridged.base.push_double_vlan) {
            // Double VLAN termination.
            push_outer_vlan();
            push_inner_vlan();
        } else {
            // If no push double vlan, inner_vlan_tag must be popped
            hdr.inner_vlan_tag.setInvalid();
#endif // WITH_DOUBLE_VLAN_TERMINATION
            // Port-based VLAN tagging; if there is no match drop the packet!

#ifdef WITH_INT
        if(!fabric_md.is_int_recirc) {
#endif // WITH_INT
            egress_vlan.apply();
#ifdef WITH_INT
        }
#endif // WITH_INT
#ifdef WITH_DOUBLE_VLAN_TERMINATION
        }
#endif // WITH_DOUBLE_VLAN_TERMINATION

        // TTL decrement and check.
        if (hdr.mpls.isValid()) {
            hdr.mpls.ttl = hdr.mpls.ttl - 1;
            if (hdr.mpls.ttl == 0) {
                fabric_v1model.drop_ctl = 1;
#ifdef WITH_INT
                fabric_md.int_report_md.drop_reason = IntDropReason_t.DROP_REASON_MPLS_TTL_ZERO;
#endif // WITH_INT
            }
        } else {
            if (hdr.ipv4.isValid() && fabric_md.bridged.base.fwd_type != FWD_BRIDGING) {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                if (hdr.ipv4.ttl == 0) {
                    fabric_v1model.drop_ctl = 1;
#ifdef WITH_INT
                    fabric_md.int_report_md.drop_reason = IntDropReason_t.DROP_REASON_IP_TTL_ZERO;
#endif // WITH_INT
                }
            } else if (hdr.ipv6.isValid() && fabric_md.bridged.base.fwd_type != FWD_BRIDGING) {
                hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
                if (hdr.ipv6.hop_limit == 0) {
                    fabric_v1model.drop_ctl = 1;
#ifdef WITH_INT
                    fabric_md.int_report_md.drop_reason = IntDropReason_t.DROP_REASON_IP_TTL_ZERO;
#endif // WITH_INT
                }
            }
        }
        fabric_v1model.egress = fabric_md; // Synch with global metadata struct
    } // end of apply{}
}
