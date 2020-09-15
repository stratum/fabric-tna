// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "../define.p4"
#include "../header.p4"

control PacketHasher(
    in parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md) {

    Hash<fabric_hash_t>(HashAlgorithm_t.CRC32) ipv4_hasher;
    Hash<fabric_hash_t>(HashAlgorithm_t.CRC32) ipv6_hasher;
    Hash<fabric_hash_t>(HashAlgorithm_t.CRC32) non_ip_hasher;
    apply {
        if (fabric_md.bridged.fwd_type == FWD_IPV4_UNICAST) {
            fabric_md.bridged.packet_hash = ipv4_hasher.get({
                fabric_md.ipv4_dst,
                fabric_md.ipv4_src,
                fabric_md.bridged.ip_proto,
                fabric_md.bridged.l4_sport,
                fabric_md.bridged.l4_dport
            });
        } else if (fabric_md.bridged.fwd_type == FWD_IPV6_UNICAST) {
            fabric_md.bridged.packet_hash = ipv6_hasher.get({
                hdr.ipv6.dst_addr, // TODO: may replace with fabric_md.ipv6_dst
                hdr.ipv6.src_addr, // if available.
                fabric_md.bridged.ip_proto,
                fabric_md.bridged.l4_sport,
                fabric_md.bridged.l4_dport
            });
        } else {
            // Bridging or other
            fabric_md.bridged.packet_hash = non_ip_hasher.get({
                hdr.ethernet.dst_addr,
                hdr.ethernet.src_addr,
                hdr.eth_type.value
            });
        }
    }
}
