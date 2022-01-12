// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

control LookupMdInit (in  ingress_headers_t hdr,
                      out lookup_metadata_t lkp_md) {

      apply {
        // we don't check if Ethernet and eth_type is valid,
        // because it is always extracted in the Parser.
        lkp_md.eth_dst = hdr.ethernet.dst_addr;
        lkp_md.eth_src = hdr.ethernet.src_addr;
        lkp_md.eth_type = hdr.eth_type.value;

        lkp_md.vlan_id = 0;
        if (hdr.vlan_tag.isValid()) {
            lkp_md.vlan_id = hdr.vlan_tag.vlan_id;
        }

        lkp_md.is_ipv4 = false;
        lkp_md.ipv4_src = 0;
        lkp_md.ipv4_dst = 0;
        lkp_md.ip_proto = 0;
        lkp_md.l4_sport = 0;
        lkp_md.l4_dport = 0;
        lkp_md.icmp_type = 0;
        lkp_md.icmp_code = 0;
        if (hdr.inner_ipv4.isValid()) {
            lkp_md.is_ipv4 = true;
            lkp_md.ipv4_src = hdr.inner_ipv4.src_addr;
            lkp_md.ipv4_dst = hdr.inner_ipv4.dst_addr;
            lkp_md.ip_proto = hdr.inner_ipv4.protocol;
            if (hdr.inner_tcp.isValid()) {
                lkp_md.l4_sport = hdr.inner_tcp.sport;
                lkp_md.l4_dport = hdr.inner_tcp.dport;
            } else if (hdr.inner_udp.isValid()) {
                lkp_md.l4_sport = hdr.inner_udp.sport;
                lkp_md.l4_dport = hdr.inner_udp.dport;
            } else if (hdr.inner_icmp.isValid()) {
                lkp_md.icmp_type = hdr.inner_icmp.icmp_type;
                lkp_md.icmp_code = hdr.inner_icmp.icmp_code;
            }
        } else if (hdr.ipv4.isValid()) {
            lkp_md.is_ipv4 = true;
            lkp_md.ipv4_src = hdr.ipv4.src_addr;
            lkp_md.ipv4_dst = hdr.ipv4.dst_addr;
            lkp_md.ip_proto = hdr.ipv4.protocol;
            if (hdr.tcp.isValid()) {
                lkp_md.l4_sport = hdr.tcp.sport;
                lkp_md.l4_dport = hdr.tcp.dport;
            } else if (hdr.udp.isValid()) {
                lkp_md.l4_sport = hdr.udp.sport;
                lkp_md.l4_dport = hdr.udp.dport;
            } else if (hdr.icmp.isValid()) {
                lkp_md.icmp_type = hdr.icmp.icmp_type;
                lkp_md.icmp_code = hdr.icmp.icmp_code;
          }
        }
      }

}
