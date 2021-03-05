// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __SPGW__
#define __SPGW__

#define DEFAULT_PDR_CTR_ID 0
#define DEFAULT_FAR_ID 0

control DecapGtpu(inout parsed_headers_t            hdr,
                  inout fabric_ingress_metadata_t   fabric_md) {
    @hidden
    action decap_inner_common() {
        // Correct parser-set metadata to use the inner header values
        fabric_md.bridged.base.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.bridged.base.ip_proto    = hdr.inner_ipv4.protocol;
        fabric_md.ipv4_src            = hdr.inner_ipv4.src_addr;
        fabric_md.ipv4_dst            = hdr.inner_ipv4.dst_addr;
        fabric_md.bridged.base.l4_sport    = fabric_md.bridged.inner_l4_sport;
        fabric_md.bridged.base.l4_dport    = fabric_md.bridged.inner_l4_dport;
        // Move GTPU and inner L3 headers out
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.gtpu.setInvalid();
    }
    @hidden
    action decap_inner_tcp() {
        decap_inner_common();
        hdr.udp.setInvalid();
        hdr.tcp = hdr.inner_tcp;
        hdr.inner_tcp.setInvalid();
    }
    @hidden
    action decap_inner_udp() {
        decap_inner_common();
        hdr.udp = hdr.inner_udp;
        hdr.inner_udp.setInvalid();
    }
    @hidden
    action decap_inner_icmp() {
        decap_inner_common();
        hdr.udp.setInvalid();
        hdr.icmp = hdr.inner_icmp;
        hdr.inner_icmp.setInvalid();
    }
    @hidden
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
        size = 3;
    }
    apply {
        decap_gtpu.apply();
    }
}

// Allows or denies recirculation of uplink packets for UE-to-UE communication.
// Should be called after GTP decap.
control UplinkRecirc(
         inout parsed_headers_t                      hdr,
         inout fabric_ingress_metadata_t             fabric_md,
         in ingress_intrinsic_metadata_t             ig_intr_md,
         inout ingress_intrinsic_metadata_for_tm_t   ig_tm_md) {

    DirectCounter<bit<16>>(CounterType_t.PACKETS) rules_counter;

    action allow() {
        // Recirculation port within same ingress pipe.
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port[8:7]++RECIRC_PORT_NUMBER;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.egress_port_set = true;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        rules_counter.count();
    }

    action deny() {
#ifdef WITH_INT
        fabric_md.int_mirror_md.drop_reason = IntDropReason_t.DROP_REASON_SPGW_UPLINK_RECIRC_DENY;
#endif // WITH_INT
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        rules_counter.count();
    }

    action miss() {
        rules_counter.count();
    }

    table rules {
        key = {
            fabric_md.ipv4_src : ternary @name("ipv4_src");
            fabric_md.ipv4_dst : ternary @name("ipv4_dst");
        }
        actions = {
            allow;
            deny;
            @defaultonly miss;
        }
        const default_action = miss;
        size = MAX_UPLINK_RECIRC_RULES;
        counters = rules_counter;
    }

    apply {
        rules.apply();
    }
}

control SpgwIngress(
        /* Fabric.p4 */
        inout parsed_headers_t                      hdr,
        inout fabric_ingress_metadata_t             fabric_md,
        /* TNA */
        in ingress_intrinsic_metadata_t             ig_intr_md,
        inout ingress_intrinsic_metadata_for_tm_t   ig_tm_md) {

    //=============================//
    //===== Misc Things ======//
    //=============================//

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    DecapGtpu() decap_gtpu_from_dbuf;
    DecapGtpu() decap_gtpu;
    UplinkRecirc() uplink_recirc;


    //=============================//
    //===== Interface Tables ======//
    //=============================//

    action load_iface(SpgwInterface src_iface) {
        // Interface type can be access, core, from_dbuf (see InterfaceType enum)
        fabric_md.spgw.src_iface    = src_iface;
        fabric_md.bridged.spgw.skip_spgw = false;
    }

    action iface_miss() {
        fabric_md.spgw.src_iface = SpgwInterface.UNKNOWN;
        fabric_md.bridged.spgw.skip_spgw = true;
    }

    // TODO: check also that gtpu.msgtype == GTP_GPDU... somewhere
    table interfaces {
        key = {
            hdr.ipv4.dst_addr  : lpm    @name("ipv4_dst_addr");  // outermost header
            hdr.gtpu.isValid() : exact  @name("gtpu_is_valid");
        }
        actions = {
            load_iface;
            @defaultonly iface_miss;
        }
        const default_action = iface_miss();
        const size = NUM_SPGW_INTERFACES;
    }

    //=============================//
    //===== PDR Tables ======//
    //=============================//

    action load_pdr(pdr_ctr_id_t    ctr_id,
                    far_id_t        far_id,
                    bool            needs_gtpu_decap) {
        fabric_md.spgw.far_id = far_id;
        fabric_md.bridged.spgw.pdr_ctr_id = ctr_id;
        fabric_md.spgw.needs_gtpu_decap = needs_gtpu_decap;
    }

    action load_pdr_qos(pdr_ctr_id_t        ctr_id,
                        far_id_t            far_id,
                        bool                needs_gtpu_decap,
                        qid_t               qid) {
        load_pdr(ctr_id, far_id, needs_gtpu_decap);
        ig_tm_md.qid = qid;
    }

    // These two tables scale well and cover the average case PDR
    table downlink_pdrs {
        key = {
            // only available ipv4 header
            hdr.ipv4.dst_addr : exact @name("ue_addr");
        }
        actions = {
            load_pdr;
            load_pdr_qos;
        }
        size = NUM_DOWNLINK_PDRS;
    }

    table uplink_pdrs {
        key = {
            hdr.ipv4.dst_addr           : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid               : exact @name("teid");
        }
        actions = {
            load_pdr;
        }
        size = NUM_UPLINK_PDRS;
    }

    //=============================//
    //===== FAR Tables ======//
    //=============================//

    action load_normal_far(bool drop,
                           bool notify_cp) {
        // general far attributes
        fabric_md.skip_forwarding = drop;
        fabric_md.skip_next = drop;
        ig_tm_md.copy_to_cpu = ((bit<1>)notify_cp) | ig_tm_md.copy_to_cpu;
        fabric_md.bridged.spgw.needs_gtpu_encap = false;
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = false;
    }

    // A commom part that being used for load_tunnel_far and load_dbuf_far
    @hidden
    action load_common_far(bool         drop,
                           bool         notify_cp,
                           l4_port_t    tunnel_src_port,
                           ipv4_addr_t  tunnel_src_addr,
                           ipv4_addr_t  tunnel_dst_addr,
                           teid_t       teid) {
        // general far attributes
        fabric_md.skip_forwarding = drop;
        fabric_md.skip_next = drop;
        ig_tm_md.copy_to_cpu = ((bit<1>)notify_cp) | ig_tm_md.copy_to_cpu;
        // GTP tunnel attributes
        fabric_md.bridged.spgw.needs_gtpu_encap = true;
        fabric_md.bridged.spgw.gtpu_teid = teid;
        fabric_md.bridged.spgw.gtpu_tunnel_sport = tunnel_src_port;
        fabric_md.bridged.spgw.gtpu_tunnel_sip = tunnel_src_addr;
        fabric_md.bridged.spgw.gtpu_tunnel_dip = tunnel_dst_addr;
        // update metadata for correct routing/hashing
        fabric_md.ipv4_src = tunnel_src_addr;
        fabric_md.ipv4_dst = tunnel_dst_addr;
    }

    action load_tunnel_far(bool         drop,
                           bool         notify_cp,
                           l4_port_t    tunnel_src_port,
                           ipv4_addr_t  tunnel_src_addr,
                           ipv4_addr_t  tunnel_dst_addr,
                           teid_t       teid) {
        load_common_far(drop, notify_cp, tunnel_src_port, tunnel_src_addr,
                        tunnel_dst_addr, teid);
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = false;
    }

    action load_dbuf_far(bool           drop,
                         bool           notify_cp,
                         l4_port_t      tunnel_src_port,
                         ipv4_addr_t    tunnel_src_addr,
                         ipv4_addr_t    tunnel_dst_addr,
                         teid_t         teid) {
        load_common_far(drop, notify_cp, tunnel_src_port, tunnel_src_addr,
                        tunnel_dst_addr, teid);
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = true;
    }

    table fars {
        key = {
            fabric_md.spgw.far_id : exact @name("far_id");
        }
        actions = {
            load_normal_far;
            load_tunnel_far;
            load_dbuf_far;
        }
        // default is drop and don't notify CP
        const default_action = load_normal_far(true, false);
        size = NUM_FARS;
    }

    //=============================//
    //===== Apply Block ======//
    //=============================//
    apply {

        if (hdr.ipv4.isValid()) {
            if (interfaces.apply().hit) {
                if (fabric_md.spgw.src_iface == SpgwInterface.FROM_DBUF) {
                    decap_gtpu_from_dbuf.apply(hdr, fabric_md);
                }
                // PDRs
                if (fabric_md.spgw.src_iface == SpgwInterface.ACCESS) {
                    uplink_pdrs.apply();
                } else if (fabric_md.spgw.src_iface == SpgwInterface.CORE ||
                            fabric_md.spgw.src_iface == SpgwInterface.FROM_DBUF) {
                    downlink_pdrs.apply();
                }
                if (fabric_md.spgw.src_iface != SpgwInterface.FROM_DBUF) {
                    pdr_counter.count(fabric_md.bridged.spgw.pdr_ctr_id);
                }

                // GTPU Decapsulate
                if (fabric_md.spgw.needs_gtpu_decap) {
                    decap_gtpu.apply(hdr, fabric_md);
                }

                // FARs
                // Load FAR info
                fars.apply();

                // Recirculate UE-to-UE traffic.
                if (fabric_md.spgw.src_iface == SpgwInterface.ACCESS && fabric_md.spgw.needs_gtpu_decap) {
                    uplink_recirc.apply(hdr, fabric_md, ig_intr_md, ig_tm_md);
                }

                // Nothing to be done immediately for forwarding or encapsulation.
                // Forwarding is done by other parts of fabric.p4, and
                // encapsulation is done in the egress

                // Needed for correct GTPU encapsulation in egress
                fabric_md.bridged.spgw.ipv4_len_for_encap = hdr.ipv4.total_len;
            }
        }
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
        hdr.outer_ipv4.total_len = fabric_md.bridged.spgw.ipv4_len_for_encap + outer_ipv4_len_additive;
        hdr.outer_ipv4.identification = 0x1513; /* From NGIC. TODO: Needs to be dynamic */
        hdr.outer_ipv4.flags = 0;
        hdr.outer_ipv4.frag_offset = 0;
        hdr.outer_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.outer_ipv4.protocol = PROTO_UDP;
        hdr.outer_ipv4.src_addr = fabric_md.bridged.spgw.gtpu_tunnel_sip;
        hdr.outer_ipv4.dst_addr = fabric_md.bridged.spgw.gtpu_tunnel_dip;
        hdr.outer_ipv4.hdr_checksum = 0; // Updated later

        hdr.outer_udp.setValid();
        hdr.outer_udp.sport = fabric_md.bridged.spgw.gtpu_tunnel_sport;
        hdr.outer_udp.dport = UDP_PORT_GTPU;
        hdr.outer_udp.len = fabric_md.bridged.spgw.ipv4_len_for_encap + outer_udp_len_additive;
        hdr.outer_udp.checksum = 0; // Updated never, due to difficulties in handling different inner headers

        hdr.outer_gtpu.setValid();
        hdr.outer_gtpu.version = GTPU_VERSION;
        hdr.outer_gtpu.pt = GTP_PROTOCOL_TYPE_GTP;
        hdr.outer_gtpu.spare = 0;
        hdr.outer_gtpu.ex_flag = 0;
        hdr.outer_gtpu.seq_flag = 0;
        hdr.outer_gtpu.npdu_flag = 0;
        hdr.outer_gtpu.msgtype = GTP_GPDU;
        hdr.outer_gtpu.msglen = fabric_md.bridged.spgw.ipv4_len_for_encap;
        hdr.outer_gtpu.teid = fabric_md.bridged.spgw.gtpu_teid;

#ifdef WITH_INT
            fabric_md.int_mirror_md.strip_gtpu = 1;
#endif // WITH_INT
    }

    @hidden
    table gtpu_encap_if_needed {
        key = {
            fabric_md.bridged.spgw.needs_gtpu_encap : exact;
        }
        actions = {
            _gtpu_encap;
        }
        const entries = {
            true : _gtpu_encap();
        }
        size = 1;
    }

    apply {
        if (!fabric_md.bridged.spgw.skip_spgw) {
            _preload_length_additives();
            gtpu_encap_if_needed.apply();
            if (!fabric_md.bridged.spgw.skip_egress_pdr_ctr) {
                pdr_counter.count(fabric_md.bridged.spgw.pdr_ctr_id);
            }
        }
    }
}
#endif // __SPGW__
