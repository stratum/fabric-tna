// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "../define.p4"
#include "../header.p4"

control Hasher(
    in parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md) {

    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) ipv4_hasher;
#ifdef WITH_SPGW
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) inner_ipv4_hasher;
#endif // WITH_SPGW
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) non_ip_hasher;

    apply {
#ifdef WITH_SPGW
        if (hdr.inner_udp.isValid()) {
            fabric_md.l4_sport = hdr.inner_udp.sport;
            fabric_md.l4_dport = hdr.inner_udp.dport;
        } else if (hdr.inner_tcp.isValid()) {
            fabric_md.l4_sport = hdr.inner_tcp.sport;
            fabric_md.l4_dport = hdr.inner_tcp.dport;
        }
        if (hdr.inner_ipv4.isValid()) {
            fabric_md.bridged.base.flow_hash = inner_ipv4_hasher.get({
                hdr.inner_ipv4.src_addr,
                hdr.inner_ipv4.dst_addr,
                hdr.inner_ipv4.protocol,
                fabric_md.l4_sport,
                fabric_md.l4_dport
            });
        } else if (hdr.ipv4.isValid()) {
#else
        if (hdr.ipv4.isValid()) {
#endif // WITH_SPGW
            fabric_md.bridged.base.flow_hash = ipv4_hasher.get({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                fabric_md.l4_sport,
                fabric_md.l4_dport
            });
        } else {
            // Not an IP packet
            fabric_md.bridged.base.flow_hash = non_ip_hasher.get({
                hdr.ethernet.dst_addr,
                hdr.ethernet.src_addr,
                hdr.eth_type.value
            });
        }
    }
}
