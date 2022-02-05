// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "shared/define.p4"
#include "shared/header.p4"

control Hasher(
    in ingress_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md) {

    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) ip_hasher;
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) gtp_flow_hasher;
#ifdef WITH_UPF
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) encap_gtp_flow_hasher;
#endif // WITH_UPF
    Hash<flow_hash_t>(HashAlgorithm_t.CRC32) non_ip_hasher;

    apply {
        // Use inner 5-tuple for the INT report filters. This is relevant for
        // GTP packets (either encapped by this switch or passthrough), as we
        // want to do dedup and anomaly detection on the inner flow only.
        fabric_md.bridged.base.inner_hash = ip_hasher.get({
            fabric_md.lkp.ipv4_src,
            fabric_md.lkp.ipv4_dst,
            fabric_md.lkp.ip_proto,
            fabric_md.lkp.l4_sport,
            fabric_md.lkp.l4_dport
        });

#ifdef WITH_UPF
        // GTP-aware ECMP for downlink packets encapped by this switch.
        if (fabric_md.bridged.upf.needs_gtpu_encap) {
            fabric_md.ecmp_hash = encap_gtp_flow_hasher.get({
                // If needs_gtpu_encap, tun_peer_id represents the GTP tunnel entpoint.
                // In addition to TEID, we use tunnel_peer_id that conveys information
                // about the source IP (UPF) and the destination IP (eNB).
                fabric_md.bridged.upf.tun_peer_id,
                fabric_md.bridged.upf.teid
            });
        } else
#endif // WITH_UPF
        // GTP-aware ECMP for passthrough GTP packets.
        if (hdr.gtpu.isValid()) {
            fabric_md.ecmp_hash = gtp_flow_hasher.get({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.gtpu.teid
            });
        } else if (fabric_md.lkp.is_ipv4) {
            // Regular 5-tuple-based ECMP. If here, the innermost IPv4 header
            // will be the only IPv4 header valid. Includes GTPU decapped pkts
            // by the upf control.
            fabric_md.ecmp_hash = fabric_md.bridged.base.inner_hash;
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
            // Not an IP packet.
            // We will never process this packet through the INT pipeline.
            fabric_md.bridged.base.inner_hash = 0;
            fabric_md.ecmp_hash = non_ip_hasher.get({
                hdr.ethernet.dst_addr,
                hdr.ethernet.src_addr,
                hdr.eth_type.value
            });
        }
    }
}
