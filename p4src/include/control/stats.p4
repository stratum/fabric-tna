// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "../header.p4"

control StatsEgress(inout parsed_headers_t hdr,
                    inout fabric_egress_metadata_t fabric_md,
                    in egress_intrinsic_metadata_t eg_intr_md) {

    ipv4_addr_t ipv4_src = 0;
    ipv4_addr_t ipv4_dst = 0;
    bit<8> ip_proto      = 0;
    l4_port_t l4_sport   = 0;
    l4_port_t l4_dport   = 0;

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) flow_counter;

    action count() {
        flow_counter.count();
    }

    table flows {
        key = {
            ipv4_src                    : ternary @name("ipv4_src");
            ipv4_dst                    : ternary @name("ipv4_dst");
            ip_proto                    : ternary @name("ip_proto");
            l4_sport                    : ternary @name("l4_sport");
            l4_dport                    : ternary @name("l4_dport");
            eg_intr_md.egress_port      : ternary @name("eg_port");
        }
        actions = {
            count;
        }
        const default_action = count;
        const size = 1024;
        counters = flow_counter;
    }

    apply {
        // Match always on the inner IPv4
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
        flows.apply();
    }
}
