// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __SPGW__
#define __SPGW__

#define DEFAULT_PDR_CTR_ID 0
#define DEFAULT_FAR_ID 0

#define NUM_UES 2048

#define MAX_PDR_COUNTERS 2*NUM_UES
#define NUM_UPLINK_PDRS NUM_UES
#define NUM_DOWNLINK_PDRS NUM_UES
#define NUM_FARS 2*NUM_UES

control SpgwIngress(
        /* Fabric.p4 */
        inout parsed_headers_t                      hdr,
        inout fabric_ingress_metadata_t             fabric_md,
        /* TNA */
        inout ingress_intrinsic_metadata_for_tm_t   ig_tm_md) {


    //=============================//
    //===== Interface Tables ======//
    //=============================//

    action set_source_iface(SpgwInterface src_iface, SpgwDirection direction,
                            bool skip_spgw) {
        // Interface type can be access, core, n6_lan, etc (see InterfaceType enum)
        // If interface is from the control plane, direction can be either up or down
        fabric_md.spgw_src_iface    = src_iface;
        fabric_md.spgw_direction    = direction;
        fabric_md.bridged.skip_spgw = skip_spgw;
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
        const default_action = set_source_iface(SpgwInterface.UNKNOWN, SpgwDirection.UNKNOWN, true);
    }

    //=============================//
    //===== PDR Tables ======//
    //=============================//

    action set_pdr_attributes(pdr_ctr_id_t ctr_id,
                              far_id_t far_id,
                              bool needs_gtpu_decap) {
        fabric_md.pdr_hit = true;
        fabric_md.far_id = far_id;
        fabric_md.bridged.pdr_ctr_id = ctr_id;
        fabric_md.needs_gtpu_decap = needs_gtpu_decap;
    }

    // These two tables scale well and cover the average case PDR
    table downlink_pdr_lookup {
        key = {
            // only available ipv4 header
            hdr.ipv4.dst_addr : exact @name("ue_addr");
        }
        actions = {
            set_pdr_attributes;
        }
        size = NUM_DOWNLINK_PDRS;
    }

    table uplink_pdr_lookup {
        key = {
            hdr.ipv4.dst_addr           : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid               : exact @name("teid");
        }
        actions = {
            set_pdr_attributes;
        }
        size = NUM_UPLINK_PDRS;
    }

    // This table scales poorly and covers uncommon PDRs
    table flexible_pdr_lookup {
        key = {
            fabric_md.spgw_src_iface         : ternary @name("src_iface");
            fabric_md.spgw_direction         : ternary @name("direction");
            // GTPU
            hdr.gtpu.isValid()               : ternary @name("gtpu_is_valid");
            hdr.gtpu.teid                    : ternary @name("teid");
            // SDF
            // outer 5-tuple
            hdr.ipv4.src_addr                : ternary @name("ipv4_src");
            hdr.ipv4.dst_addr                : ternary @name("ipv4_dst");
            hdr.ipv4.protocol                : ternary @name("ip_proto");
            fabric_md.bridged.l4_sport       : ternary @name("l4_sport");
            fabric_md.bridged.l4_dport       : ternary @name("l4_dport");
            // inner 5-tuple
            hdr.inner_ipv4.src_addr          : ternary @name("inner_ipv4_src");
            hdr.inner_ipv4.dst_addr          : ternary @name("inner_ipv4_dst");
            hdr.inner_ipv4.protocol          : ternary @name("inner_ip_proto");
            fabric_md.bridged.inner_l4_sport : ternary @name("inner_l4_sport");
            fabric_md.bridged.inner_l4_dport : ternary @name("inner_l4_dport");
        }
        actions = {
            set_pdr_attributes;
        }
        const default_action = set_pdr_attributes(DEFAULT_PDR_CTR_ID, DEFAULT_FAR_ID, false);
    }

    //=============================//
    //===== FAR Tables ======//
    //=============================//

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
        fabric_md.bridged.needs_gtpu_encap = true;
        fabric_md.bridged.gtpu_teid = teid;
        fabric_md.bridged.gtpu_tunnel_sport = tunnel_src_port;
        fabric_md.bridged.gtpu_tunnel_sip = tunnel_src_addr;
        fabric_md.bridged.gtpu_tunnel_dip = tunnel_dst_addr;
        // update metadata for correct routing/hashing
        fabric_md.ipv4_src = tunnel_src_addr;
        fabric_md.ipv4_dst = tunnel_dst_addr;
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
        const default_action = load_normal_far_attributes(true, true);
        size = NUM_FARS;
    }

    //=============================//
    //===== Misc Things ======//
    //=============================//

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    @hidden
    action decap_inner_common() {
        // Correct parser-set metadata to use the inner header values
        fabric_md.bridged.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.bridged.ip_proto    = hdr.inner_ipv4.protocol;
        fabric_md.ipv4_src            = hdr.inner_ipv4.src_addr;
        fabric_md.ipv4_dst            = hdr.inner_ipv4.dst_addr;
        fabric_md.bridged.l4_sport    = fabric_md.bridged.inner_l4_sport;
        fabric_md.bridged.l4_dport    = fabric_md.bridged.inner_l4_dport;
        // Move GTPU and inner L3 headers out
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.gtpu.setInvalid();
    }
    action decap_inner_tcp() {
        decap_inner_common();
        hdr.udp.setInvalid();
        hdr.tcp = hdr.inner_tcp;
        hdr.inner_tcp.setInvalid();
    }
    action decap_inner_udp() {
        decap_inner_common();
        hdr.udp = hdr.inner_udp;
        hdr.inner_udp.setInvalid();
    }
    action decap_inner_icmp() {
        decap_inner_common();
        hdr.udp.setInvalid();
        hdr.icmp = hdr.inner_icmp;
        hdr.inner_icmp.setInvalid();
    }
    action decap_inner_unknown() {
        decap_inner_common();
        hdr.udp.setInvalid();
    }
    @hidden
    table decap_gtpu {
        key = {
            hdr.inner_tcp.isValid()  : exact;
            hdr.inner_udp.isValid()  : exact;
            hdr.inner_icmp.isValid() : exact;
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

    //=============================//
    //===== Apply Block ======//
    //=============================//
    apply {

        // Interfaces
        interface_lookup.apply();

        // If interface table missed, or the interface skips PDRs/FARs (TODO: is that a thing?)
        if (fabric_md.bridged.skip_spgw) return;

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
        pdr_counter.count(fabric_md.bridged.pdr_ctr_id);

        // GTPU Decapsulate
        if (fabric_md.needs_gtpu_decap) {
            decap_gtpu.apply();
        }

        // FARs
        // Load FAR info
        far_lookup.apply();

        if (fabric_md.notify_spgwc) {
            // TODO: should notification involve something other than cloning?
            ig_tm_md.copy_to_cpu = 1;
        }
        if (fabric_md.far_dropped) {
            // Do dropping in the same way as fabric's filtering.p4, so we can traverse
            // the ACL table, which is good for cases like DHCP.
            fabric_md.skip_forwarding = true;
            fabric_md.skip_next = true;
        }

        // Nothing to be done immediately for forwarding or encapsulation.
        // Forwarding is done by other parts of fabric.p4, and
        // encapsulation is done in the egress

        // Needed for correct GTPU encapsulation in egress
        // TODO: This is from v1model. Is it still needed?
        fabric_md.bridged.spgw_ipv4_len = hdr.ipv4.total_len;
    }
}


//====================================//
//============== Egress ==============//
//====================================//
control SpgwEgress(
        inout parsed_headers_t hdr,
        inout fabric_egress_metadata_t fabric_md) {

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    bit<16> outer_ipv4_len_additive;
    bit<16> outer_udp_len_additive;

    /*
    This roundabout action is used to circumvent a bug of unknown origin that was experienced
    in September 2020 when the header size defines were used directly in the _gtpu_encap action.
    An addition using one of the constants would yield a wrong result on hardware, despite there being
    no apparent issues with the addition primitive and its inputs in the compiler output.
    */
    @hidden
    action _preload_length_additives() {
        outer_ipv4_len_additive = IPV4_HDR_BYTES + UDP_HDR_BYTES + GTP_HDR_BYTES;
        outer_udp_len_additive = UDP_HDR_BYTES + GTP_HDR_BYTES;
    }

    @hidden
    action _gtpu_encap() {
        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.version = IP_VERSION_4;
        hdr.outer_ipv4.ihl = IPV4_MIN_IHL;
        hdr.outer_ipv4.dscp = 0;
        hdr.outer_ipv4.ecn = 0;
        hdr.outer_ipv4.total_len = fabric_md.bridged.spgw_ipv4_len + outer_ipv4_len_additive;
        hdr.outer_ipv4.identification = 0x1513; /* From NGIC. TODO: Needs to be dynamic */
        hdr.outer_ipv4.flags = 0;
        hdr.outer_ipv4.frag_offset = 0;
        hdr.outer_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.outer_ipv4.protocol = PROTO_UDP;
        hdr.outer_ipv4.src_addr = fabric_md.bridged.gtpu_tunnel_sip;
        hdr.outer_ipv4.dst_addr = fabric_md.bridged.gtpu_tunnel_dip;
        hdr.outer_ipv4.hdr_checksum = 0; // Updated later

        hdr.outer_udp.setValid();
        hdr.outer_udp.sport = fabric_md.bridged.gtpu_tunnel_sport;
        hdr.outer_udp.dport = UDP_PORT_GTPU;
        hdr.outer_udp.len = fabric_md.bridged.spgw_ipv4_len + outer_udp_len_additive;
        hdr.outer_udp.checksum = 0; // Updated never, due to difficulties in handling different inner headers

        hdr.outer_gtpu.setValid();
        hdr.outer_gtpu.version = GTPU_VERSION;
        hdr.outer_gtpu.pt = GTP_PROTOCOL_TYPE_GTP;
        hdr.outer_gtpu.spare = 0;
        hdr.outer_gtpu.ex_flag = 0;
        hdr.outer_gtpu.seq_flag = 0;
        hdr.outer_gtpu.npdu_flag = 0;
        hdr.outer_gtpu.msgtype = GTP_GPDU;
        hdr.outer_gtpu.msglen = fabric_md.bridged.spgw_ipv4_len;
        hdr.outer_gtpu.teid = fabric_md.bridged.gtpu_teid;

#ifdef WITH_INT
            fabric_md.int_mirror_md.strip_gtpu = 1;
#endif // WITH_INT
    }

    @hidden
    table gtpu_encap_if_needed {
        key = {
            fabric_md.bridged.needs_gtpu_encap : exact;
        }
        actions = {
            _gtpu_encap;
        }
        const entries = {
            (true) : _gtpu_encap();
        }
        size = 1;
    }

    apply {
        if (!fabric_md.bridged.skip_spgw) {
            pdr_counter.count(fabric_md.bridged.pdr_ctr_id);
            _preload_length_additives();
            gtpu_encap_if_needed.apply();
        }
    }
}
#endif // __SPGW__
