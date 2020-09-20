// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "../define.p4"
#include "../header.p4"

control Hasher(
    in parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md) {

    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) ipv4_hasher;
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) ipv6_hasher;
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) non_ip_hasher;

    apply {
        if (hdr.ipv4.isValid()) {
            fabric_md.bridged.flow_hash = ipv4_hasher.get({
                fabric_md.ipv4_dst,
                fabric_md.ipv4_src,
                fabric_md.bridged.ip_proto,
                fabric_md.bridged.l4_sport,
                fabric_md.bridged.l4_dport
            });
        } else if (hdr.ipv6.isValid()) {
            fabric_md.bridged.flow_hash = ipv6_hasher.get({
                hdr.ipv6.dst_addr, // TODO: may replace with fabric_md.ipv6_dst
                hdr.ipv6.src_addr, // if available.
                fabric_md.bridged.ip_proto,
                fabric_md.bridged.l4_sport,
                fabric_md.bridged.l4_dport
            });
        } else {
            // Not an IP packet
            fabric_md.bridged.flow_hash = non_ip_hasher.get({
                hdr.ethernet.dst_addr,
                hdr.ethernet.src_addr,
                hdr.eth_type.value
            });
        }
    }
}
