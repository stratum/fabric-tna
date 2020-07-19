// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>
#include <tna.p4>

#include "../define.p4"
#include "../header.p4"

control Acl (inout parsed_headers_t hdr,
             inout fabric_ingress_metadata_t fabric_md,
             in ingress_intrinsic_metadata_t ig_intr_md,
             inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
             inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    /*
     * ACL Table.
     */
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) acl_counter;

    action set_next_id_acl(next_id_t next_id) {
        fabric_md.next_id = next_id;
        acl_counter.count();
    }

    // Send immendiatelly to CPU - skip the rest of ingress.
    action punt_to_cpu() {
        ig_intr_md_for_tm.ucast_egress_port = CPU_PORT;
        fabric_md.skip_next = true;
        acl_counter.count();
    }

    action copy_to_cpu() {
        ig_intr_md_for_tm.copy_to_cpu = 1;
        acl_counter.count();
    }

    // Set mirror with session/clone id
    action set_clone_session_id(bit<32> clone_id) {
        fabric_md.is_mirror = true;
        fabric_md.mirror_id = clone_id[9:0];
        acl_counter.count();
    }

    action drop() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
        fabric_md.skip_next = true;
        acl_counter.count();
    }

    action nop_acl() {
        acl_counter.count();
    }

    table acl {
        key = {
            ig_intr_md.ingress_port: ternary @name("ig_port"); // 9
            fabric_md.ip_proto: ternary @name("ip_proto"); // 8
            fabric_md.l4_sport: ternary @name("l4_sport"); // 16
            fabric_md.l4_dport: ternary @name("l4_dport"); // 16
            hdr.ethernet.dst_addr: ternary @name("eth_dst"); // 48
            hdr.ethernet.src_addr: ternary @name("eth_src"); // 48
            hdr.vlan_tag.vlan_id: ternary @name("vlan_id"); // 12
            hdr.eth_type.value: ternary @name("eth_type"); //16
            fabric_md.ipv4_src_addr: ternary @name("ipv4_src"); // 32
            fabric_md.ipv4_dst_addr: ternary @name("ipv4_dst"); // 32
            hdr.icmp.icmp_type: ternary @name("icmp_type"); // 8
            hdr.icmp.icmp_code: ternary @name("icmp_code"); // 8
        }

        actions = {
            set_next_id_acl;
            punt_to_cpu;
            copy_to_cpu;
            set_clone_session_id;
            drop;
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
