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

    ipv4_addr_t ipv4_src    = 0;
    ipv4_addr_t ipv4_dst    = 0;
    bit<8> ip_proto         = 0;
    l4_port_t l4_sport      = 0;
    l4_port_t l4_dport      = 0;

    /*
     * ACL Table.
     */
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) acl_counter;

    action set_next_id_acl(next_id_t next_id) {
        fabric_md.next_id = next_id;
        acl_counter.count();
    }

    action punt_to_cpu() {
        ig_intr_md_for_tm.copy_to_cpu = 1;
        ig_intr_md_for_dprsr.drop_ctl = 1;
        fabric_md.skip_next = true;
        acl_counter.count();
    }

    action copy_to_cpu() {
        ig_intr_md_for_tm.copy_to_cpu = 1;
        acl_counter.count();
    }

    action drop() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.int_mirror_md.drop_reason = IntDropReason_t.DROP_REASON_ACL_DENY;
#endif // WITH_INT
        acl_counter.count();
    }

    /*
     * The next_mpls and next_vlan tables are applied before the acl table.
     * So, if this action is applied, even though skip_next is set to true
     * the packet might get forwarded with unexpected MPLS and VLAG tags.
     */
    action set_output_port(PortId_t port_num) {
        ig_intr_md_for_tm.ucast_egress_port = port_num;
        fabric_md.egress_port_set = true;
        fabric_md.skip_next = true;
        acl_counter.count();
    }

    action nop_acl() {
        acl_counter.count();
    }

    table acl {
        key = {
            ig_intr_md.ingress_port     : ternary @name("ig_port");   // 9
            hdr.ethernet.dst_addr       : ternary @name("eth_dst");   // 48
            hdr.ethernet.src_addr       : ternary @name("eth_src");   // 48
            hdr.vlan_tag.vlan_id        : ternary @name("vlan_id");   // 12
            hdr.eth_type.value          : ternary @name("eth_type");  // 16
            ipv4_src                    : ternary @name("ipv4_src");  // 32
            ipv4_dst                    : ternary @name("ipv4_dst");  // 32
            ip_proto                    : ternary @name("ip_proto");  // 8
            hdr.icmp.icmp_type          : ternary @name("icmp_type"); // 8
            hdr.icmp.icmp_code          : ternary @name("icmp_code"); // 8
            l4_sport                    : ternary @name("l4_sport");  // 16
            l4_dport                    : ternary @name("l4_dport");  // 16
            fabric_md.port_type         : ternary @name("port_type"); // 2
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
        if (hdr.gtpu.isValid() && hdr.inner_ipv4.isValid()) {
            ipv4_src = hdr.inner_ipv4.src_addr;
            ipv4_dst = hdr.inner_ipv4.dst_addr;
            ip_proto = hdr.inner_ipv4.protocol;
            if (hdr.inner_tcp.isValid()) {
                l4_sport = hdr.inner_tcp.sport;
                l4_dport = hdr.inner_tcp.dport;
            } else if (hdr.inner_udp.isValid()) {
                l4_sport = hdr.inner_udp.sport;
                l4_dport = hdr.inner_udp.dport;
            }
        } else if (hdr.ipv4.isValid()) {
            ipv4_src = hdr.ipv4.src_addr;
            ipv4_dst = hdr.ipv4.dst_addr;
            ip_proto = hdr.ipv4.protocol;
            if (hdr.tcp.isValid()) {
                l4_sport = hdr.tcp.sport;
                l4_dport = hdr.tcp.dport;
            } else if (hdr.udp.isValid()) {
                l4_sport = hdr.udp.sport;
                l4_dport = hdr.udp.dport;
            }
        }
        acl.apply();
    }
}
