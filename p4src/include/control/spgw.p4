/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SPGW__
#define __SPGW__

#define MAX_PDR_COUNTERS 1024
#define DEFAULT_PDR_CTR_ID 0
#define DEFAULT_FAR_ID 0

control SpgwIngress(
        inout parsed_headers_t hdr,
        inout fabric_ingress_metadata_t fabric_md) {


    action set_source_iface(SpgwInterface src_iface, SpgwDirection direction, 
                            bool skip_spgw) {
        // Interface type can be access, core, n6_lan, etc (see InterfaceType enum)
        // If interface is from the control plane, direction can be either up or down
        fabric_md.spgw_src_iface = src_iface;
        fabric_md.spgw_direction = direction;
        fabric_md.skip_spgw      = skip_spgw;
    }

    // TODO: check also that gtpu.msgtype == GTP_GPDU... somewhere
    table interface_lookup {
        key = {
            hdr.ipv4.dst_addr  : lpm    @name("ipv4_dst_addr");  // outermost header
            hdr.gtpu.isValid() : exact  @name("gtpu_is_valid");
        }
        actions = {
            set_source_iface;
        }
        const default_action = set_source_iface(SpgwInterfaceType.UNKNOWN, SpgwDirection.UNKNOWN, true);
    }


    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    @hidden
    action gtpu_decap() {
        // grab information from the tunnel that we'll need later
        fabric_md.gtpu_teid = hdr.gtpu.teid;
        fabric_md.gtpu_tunnel_sip = hdr.outer_ipv4.dst_addr;
        // update metadata src and dst addresses with the inner packet 
        fabric_md.ipv4_src_addr = hdr.ipv4.src_addr;
        fabric_md.ipv4_dst_addr = hdr.ipv4.dst_addr;
        // decap
        outer_ipv4.setInvalid();
        outer_udp.setInvalid();
        gtpu.setInvalid();
    }

    action set_pdr_attributes(ctr_id_t ctr_id,
                              far_id_t far_id,
                              bool needs_gtpu_decap) {
        fabric_md.pdr_hit = true;
        fabric_md.pdr_ctr_id = ctr_id;
        fabric_md.far_id = far_id;
        fabric_md.needs_gtpu_decap = needs_gtpu_decap;
    }

    // These two tables scale well and cover the average case PDR
    table downlink_pdr_lookup {
        key = {
            hdr.ipv4.dst_addr : exact @name("ue_addr");
        }
        actions = {
            set_pdr_attributes;
        }
    }
    table uplink_pdr_lookup {
        key = {
            // tunnel_dst_addr will be static for Q2 target. Can remove if need more scaling
            hdr.ipv4.dst_addr           : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid               : exact @name("teid");
            hdr.inner_ipv4.src_addr     : exact @name("ue_addr");
        }
        actions = {
            set_pdr_attributes;
        }
    }
    // This table scales poorly and covers uncommon PDRs
    table flexible_pdr_lookup {
        key = {
            fabric_md.spgw_src_iface    : ternary @name("src_iface");
            // GTPU
            hdr.gtpu.isValid()          : ternary @name("gtpu_is_valid");
            hdr.gtpu.teid               : ternary @name("teid");
            // SDF (5-tuple)
            // outer
            hdr.ipv4.src_addr           : ternary @name("ipv4_src");
            hdr.ipv4.dst_addr           : ternary @name("ipv4_dst");
            hdr.ipv4.protocol           : ternary @name("ip_proto");
            fabric_md.l4_sport          : ternary @name("l4_sport");
            fabric_md.l4_dport          : ternary @name("l4_dport");
            // inner
            hdr.inner_ipv4.src_addr     : ternary @name("inner_ipv4_src");
            hdr.inner_ipv4.dst_addr     : ternary @name("inner_ipv4_dst");
            hdr.inner_ipv4.protocol     : ternary @name("inner_ip_proto");
            fabric_md.inner_l4_sport    : ternary @name("inner_l4_sport");
            fabric_md.inner_l4_dport    : ternary @name("inner_l4_dport");
        }
        actions = {
            set_pdr_attributes;
        }
        const default_action = set_pdr_attributes(DEFAULT_PDR_CTR_ID, DEFAULT_FAR_ID, false);
    }

    action load_normal_far_attributes(bool drop,
                                      bool notify_cp) {
        // general far attributes
        fabric_md.far_dropped = drop;
        fabric_md.notify_spgwc   = notify_cp;
    }
    action load_tunnel_far_attributes(bool      drop,
                                      bool      notify_cp,
                                      bit<16>   tunnel_src_port,
                                      bit<32>   tunnel_src_addr,
                                      bit<32>   tunnel_dst_addr,
                                      teid_t    teid) {
        // general far attributes
        fabric_md.far_dropped = drop;
        fabric_md.notify_spgwc = notify_cp;
        // GTP tunnel attributes
        fabric_md.needs_gtpu_encap = true;
        fabric_md.gtpu_teid = teid;
        fabric_md.gtpu_tunnel_sip = tunnel_src_addr;
        fabric_md.gtpu_tunnel_dip = tunnel_dst_addr;
        // update metadata for correct routing/hashing
        fabric_md.ipv4_src_addr = tunnel_src_addr;
        fabric_md.ipv4_dst_addr = tunnel_dst_addr;
        fabric_md.l4_sport = tunnel_src_port;
        fabric_md.l4_dport = UDP_PORT_GTPU;
    }


    table far_lookup {
        key = {
            fabric_md.far_id : exact @name("far_id");
        }
        actions = {
            load_normal_far_attributes;
            load_tunnel_far_attributes;
        }
        // default is drop and don't notify CP
        const default_action = load_normal_far_attributes(1w1, 1w0);
    }

    @hidden 
    action decap_inner_common() {
        // Correct parser-set metadata
        fabric_md.ip_eth_type   = ETHERTYPE_IPV4
        fabric_md.ip_proto      = hdr.inner_ipv4.protocol;
        fabric_md.ipv4_src_addr = hdr.inner_ipv4.src_addr;
        fabric_md.ipv4_dst_addr = hdr.inner_ipv4.dst_addr;
        fabric_md.l4_sport      = fabric_md.inner_l4_sport;
        fabric_md.l4_dport      = fabric_md.inner_l4_dport;
        // Move GTPU and inner L3 headers out
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.gtpu.setInvalid();
    }
    action decap_inner_tcp() {
        decap_inner_common();
        hdr.tcp = hdr.inner_tcp;
        hdr.inner_tcp.setInvalid();
        hdr.udp.setInvalid();
    }
    action decap_inner_udp() {
        decap_inner_common();
        hdr.udp = hdr.inner_udp();
        hdr.inner_udp.setInvalid();
    }
    action decap_inner_icmp() {
        decap_inner_common();
        hdr.icmp = hdr.inner_icmp;
        hdr.inner_icmp.setInvalid();
        hdr.udp.setInvalid();
    }
    action decap_inner_unknown() {
        decap_inner_common();
        hdr.udp.setInvalid();
    }

    table decap_gtpu {
        key = {
            hdr.inner_tcp.isValid()     : exact;
            hdr.inner_udp.isValid()     : exact;
            hdr.inner_icmp.isValid()    : exact;
        }
        actions = {
            decap_inner_tcp;
            decap_inner_udp;
            decap_inner_icmp;
            decap_inner_unknown;
        }
        const default_action = decap_inner_unknown;
        const entries = {
            (true,  false, false) : decap_inner_tcp();
            (false, true,  false) : decap_inner_udp();
            (false, false, true)  : decap_inner_icmp();
        }
        size = 4;
    }

    apply {

        // Interfaces
        interface_lookup.apply()

        // If interface table missed, or the interface skips PDRs/FARs (TODO: is that a thing?)
        if (fabric_md.skip_spgw) return;

        // PDRs
        // Try the efficient PDR tables first (This PDR partitioning only works
        // if the PDRs do not overlap. FIXME: does this assumption hold?)
        if (hdr.gtpu.isValid()) {
            uplink_pdr_lookup.apply();
        } else {
            downlink_pdr_lookup.apply();
        }
        // Inefficient PDR table if efficient tables missed
        if (!fabric_md.pdr_hit) {
            flexible_pdr_lookup.apply();
        }
        pdr_counter.count(fabric_md.pdr_ctr_id);
        
        // GTPU Decapsulate
        if (fabric_md.needs_gtpu_decap) {
            decap_gtpu.apply()
        }

        // FARs
        // Load FAR info
        far_lookup.apply();

        if (fabric_md.notify_spgwc) {
            // TODO: cpu clone session here
        }
        if (fabric_md.spgw.far_dropped) {
            // Do dropping in the same way as fabric's filtering.p4, so we can traverse
            // the ACL table, which is good for cases like DHCP.
            fabric_md.skip_forwarding = true;
            fabric_md.skip_next = true;
        }

        // Nothing to be done immediately for forwarding or encapsulation.
        // Forwarding is done by other parts of fabric.p4, and
        // encapsulation is done in the egress

        // Needed for correct GTPU encapsulation in egress
        fabric_md.spgw_ipv4_len = hdr.ipv4.total_len;
    }
}


control SpgwEgress(
        inout parsed_headers_t hdr,
        inout fabric_ingress_metadata_t fabric_md) {

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;


    @hidden
    action gtpu_encap() {
        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.version = IP_VERSION_4;
        hdr.outer_ipv4.ihl = IPV4_MIN_IHL;
        hdr.outer_ipv4.dscp = 0;
        hdr.outer_ipv4.ecn = 0;
        hdr.outer_ipv4.total_len = hdr.ipv4.total_len
                + (IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_SIZE);
        hdr.outer_ipv4.identification = 0x1513; /* From NGIC. TODO: Needs to be dynamic */
        hdr.outer_ipv4.flags = 0;
        hdr.outer_ipv4.frag_offset = 0;
        hdr.outer_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.outer_ipv4.protocol = PROTO_UDP;
        hdr.outer_ipv4.src_addr = fabric_md.gtpu_tunnel_sip;
        hdr.outer_ipv4.dst_addr = fabric_md.gtpu_tunnel_dip;
        hdr.outer_ipv4.hdr_checksum = 0; // Updated never

        hdr.outer_udp.setValid();
        hdr.outer_udp.sport = fabric_md.gtpu_tunnel_sport;;
        hdr.outer_udp.dport = UDP_PORT_GTPU;
        hdr.outer_udp.len = fabric_md.spgw_ipv4_len
                + (UDP_HDR_SIZE + GTP_HDR_SIZE);
        hdr.outer_udp.checksum = 0; // Updated later, if WITH_SPGW_UDP_CSUM_UPDATE


        hdr.gtpu.setValid();
        hdr.gtpu.version = GTPU_VERSION;
        hdr.gtpu.pt = GTP_PROTOCOL_TYPE_GTP;
        hdr.gtpu.spare = 0;
        hdr.gtpu.ex_flag = 0;
        hdr.gtpu.seq_flag = 0;
        hdr.gtpu.npdu_flag = 0;
        hdr.gtpu.msgtype = GTP_GPDU;
        hdr.gtpu.msglen = fabric_md.spgw_ipv4_len;
        hdr.gtpu.teid = fabric_md.gtpu_teid;
    }

    apply {
        if (fabric_md.skip_spgw) return;
        pdr_counter.count(fabric_md.pdr_ctr_id);

        if (fabric_md.needs_gtpu_encap) {
            gtpu_encap();
        }
    }
}


control update_gtpu_checksum(
        inout ipv4_t gtpu_ipv4,
        inout udp_t  gtpu_udp,
        in    gtpu_t gtpu,
        in    ipv4_t ipv4,
        in    udp_t  udp
    ) {
    apply {
        // Compute outer IPv4 checksum.
        update_checksum(gtpu_ipv4.isValid(),
            {
                gtpu_ipv4.version,
                gtpu_ipv4.ihl,
                gtpu_ipv4.dscp,
                gtpu_ipv4.ecn,
                gtpu_ipv4.total_len,
                gtpu_ipv4.identification,
                gtpu_ipv4.flags,
                gtpu_ipv4.frag_offset,
                gtpu_ipv4.ttl,
                gtpu_ipv4.protocol,
                gtpu_ipv4.src_addr,
                gtpu_ipv4.dst_addr
            },
            gtpu_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );

#ifdef WITH_SPGW_UDP_CSUM_UPDATE
        // Compute outer UDP checksum.
        update_checksum_with_payload(gtpu_udp.isValid(),
            {
                gtpu_ipv4.src_addr,
                gtpu_ipv4.dst_addr,
                8w0,
                gtpu_ipv4.protocol,
                gtpu_udp.len,
                gtpu_udp.sport,
                gtpu_udp.dport,
                gtpu_udp.len,
                gtpu,
                ipv4,
                // FIXME: we are assuming only UDP for downlink packets
                // How to conditionally switch between UDP/TCP/ICMP?
                udp
            },
            gtpu_udp.checksum,
            HashAlgorithm.csum16
        );
#endif // WITH_SPGW_UDP_CSUM_UPDATE
    }
}

#endif
