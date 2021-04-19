// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "../define.p4"
#include "../header.p4"

// Used for ECMP hashing.
struct gtp_flow_t {
    bit<32>   ipv4_src;
    bit<32>   ipv4_dst;
    teid_t    gtpu_teid;
}

control Hasher(
    in parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md) {

    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) ip_hasher;
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) gtp_flow_hasher;
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) non_ip_hasher;

    apply {
        flow_hash_t inner_hash;

        // checks if inner header is IPv4
        if (fabric_md.acl_lkp.is_ipv4) {
            gtp_flow_t to_hash;
            bool calc_gtp_hash = false;

            // we always need to calculate hash from the inner IPv4 header for the INT reporter.
            inner_hash = ip_hasher.get(fabric_md.acl_lkp);

            // use inner hash by default
            fabric_md.ecmp_hash = inner_hash;

            // if an outer GTP header exists, use it to perform GTP-aware ECMP
            if (hdr.gtpu.isValid()) {
                to_hash.ipv4_src = hdr.ipv4.src_addr;
                to_hash.ipv4_dst = hdr.ipv4.dst_addr;
                to_hash.gtpu_teid = hdr.gtpu.teid;
                calc_gtp_hash = true;
            }

#ifdef WITH_SPGW
            // enable GTP-aware ECMP for downlink packets.
            if (fabric_md.bridged.spgw.needs_gtpu_encap) {
                to_hash.ipv4_src = fabric_md.bridged.spgw.gtpu_tunnel_sip;
                to_hash.ipv4_dst = fabric_md.bridged.spgw.gtpu_tunnel_dip;
                to_hash.gtpu_teid = fabric_md.bridged.spgw.gtpu_teid;
                calc_gtp_hash = true;
            }
#endif // WITH_SPGW

            if (calc_gtp_hash) {
                fabric_md.ecmp_hash = gtp_flow_hasher.get(to_hash);
            }

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
            // Inner header is not an IPv4 packet
            inner_hash = non_ip_hasher.get({
                hdr.ethernet.dst_addr,
                hdr.ethernet.src_addr,
                hdr.eth_type.value
            });
        }

#ifdef WITH_INT
            fabric_md.bridged.int_bmd.inner_hash = inner_hash;
#endif // WITH_INT

    }
}
