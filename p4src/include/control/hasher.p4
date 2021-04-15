// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "../define.p4"
#include "../header.p4"

// Used for ECMP hashing.
struct flow_t {
    bit<32>   ipv4_src;
    bit<32>   ipv4_dst;
    bit<8>    ip_proto;
    l4_port_t l4_sport;
    l4_port_t l4_dport;
    teid_t    gtpu_teid;
}

control Hasher(
    in parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md) {

    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) int_hasher;
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) ipv4_hasher;
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) non_ip_hasher;

    apply {
        if (fabric_md.acl_lkp.is_ipv4) {
            // we always need to calculate hash from inner headers for the INT reporter
            fabric_md.bridged.base.int_hash = int_hasher.get(fabric_md.acl_lkp);

            // if not a GTP flow, use hash calculated from inner headers
            fabric_md.flow_hash = fabric_md.bridged.base.int_hash;
#ifdef WITH_SPGW
            if (hdr.gtpu.isValid()) {
                flow_t to_hash;
                // for GTP-encapsulated IPv4 packet use outer IPv4 header for hashing
                to_hash.gtpu_teid = hdr.gtpu.teid;
                to_hash.ipv4_src = hdr.ipv4.src_addr;
                to_hash.ipv4_dst = hdr.ipv4.dst_addr;
                to_hash.ip_proto = hdr.ipv4.protocol;
                // avoid the impact of the PHV overlay
                to_hash.l4_sport = 0;
                to_hash.l4_dport = 0;
                // this should always be true for the GTP-encapsulated packets
                if (hdr.udp.isValid()) {
                    to_hash.l4_sport = hdr.udp.sport;
                    to_hash.l4_dport = hdr.udp.dport;
                }
                fabric_md.flow_hash = ipv4_hasher.get(to_hash);
            }
#endif // WITH_SPGW
        }
        // FIXME: remove ipv6 support or test it
        //  https://github.com/stratum/fabric-tna/pull/227
        // else if (hdr.ipv6.isValid()) {
        //     fabric_md.bridged.base.flow_hash = ipv6_hasher.get({
        //         hdr.ipv6.src_addr,
        //         hdr.ipv6.dst_addr,
        //         fabric_md.ip_proto,
        //         fabric_md.l4_sport,
        //         fabric_md.l4_dport
        //     });
        // }
        else {
            // Not an IP packet
            fabric_md.flow_hash = non_ip_hasher.get({
                hdr.ethernet.dst_addr,
                hdr.ethernet.src_addr,
                hdr.eth_type.value
            });
        }
    }
}
