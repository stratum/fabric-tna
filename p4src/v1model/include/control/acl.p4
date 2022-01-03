// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>
#include <v1model.p4>

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

control Acl (inout ingress_headers_t hdr,
             inout fabric_ingress_metadata_t fabric_md,
             inout standard_metadata_t standard_md) {

    /*
     * ACL Table.
     */
    direct_counter(CounterType.packets_and_bytes) acl_counter;

    action set_next_id_acl(next_id_t next_id) {
        fabric_md.next_id = next_id;
        acl_counter.count();
        // FIXME: We have to rewrite other fields to perform correct override action
        // e.g. forwarding type == "ROUTING" while we want to override the action to "BRIDGE" in NEXT table
        fabric_md.skip_next = false;
        // TODO: drop_ctl should set to 0 here when drop_ctl is supported
    }

    action copy_to_cpu() {
        clone3(CloneType.I2E,
            (bit<32>) PACKET_IN_MIRROR_SESSION_ID,
            {standard_md.ingress_port}
        );
        acl_counter.count();
    }

    action punt_to_cpu() {
        copy_to_cpu();
        fabric_md.skip_next = true;
        fabric_md.punt_to_cpu = true;
        mark_to_drop(standard_md);
    }

    action drop() {
        mark_to_drop(standard_md);
        fabric_md.skip_next = true;
        acl_counter.count();
    }

    /*
     * The next_mpls and next_vlan tables are applied before the acl table.
     * So, if this action is applied, even though skip_next is set to true
     * the packet might get forwarded with unexpected MPLS and VLAG tags.
     */
    action set_output_port(FabricPortId_t port_num) {
        // FIXME: If the forwarding type is ROUTING, although we have overriden the action to Bridging here
        // ttl will still -1 in the egress pipeline
        standard_md.egress_spec = (PortId_t)port_num;
        fabric_md.egress_port_set = true;
        fabric_md.skip_next = true;
        acl_counter.count();
    }

    action nop_acl() {
        acl_counter.count();
    }

    table acl {
        key = {
            standard_md.ingress_port         : ternary @name("ig_port");   // 9
            fabric_md.lkp.eth_dst            : ternary @name("eth_dst");   // 48
            fabric_md.lkp.eth_src            : ternary @name("eth_src");   // 48
            fabric_md.lkp.vlan_id            : ternary @name("vlan_id");   // 12
            fabric_md.lkp.eth_type           : ternary @name("eth_type");  // 16
            fabric_md.lkp.ipv4_src           : ternary @name("ipv4_src");  // 32
            fabric_md.lkp.ipv4_dst           : ternary @name("ipv4_dst");  // 32
            fabric_md.lkp.ip_proto           : ternary @name("ip_proto");  // 8
            fabric_md.lkp.icmp_type          : ternary @name("icmp_type"); // 8
            fabric_md.lkp.icmp_code          : ternary @name("icmp_code"); // 8
            fabric_md.lkp.l4_sport           : ternary @name("l4_sport");  // 16
            fabric_md.lkp.l4_dport           : ternary @name("l4_dport");  // 16
            fabric_md.ig_port_type           : ternary @name("ig_port_type"); // 2
        }

        actions = {
            set_next_id_acl;
            punt_to_cpu;
            copy_to_cpu;
            drop;
            set_output_port;
            nop_acl;
        }

        const default_action = nop_acl();
        size = ACL_TABLE_SIZE;
        counters = acl_counter;
    }

    apply {
        acl.apply();
    }
}
