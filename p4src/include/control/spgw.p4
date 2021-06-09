// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __SPGW__
#define __SPGW__

#define DEFAULT_PDR_CTR_ID 0
#define DEFAULT_FAR_ID 0

control DecapGtpu(inout ingress_headers_t            hdr,
                  inout fabric_ingress_metadata_t   fabric_md) {
    @hidden
    action decap_inner_common() {
        fabric_md.bridged.base.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.routing_ipv4_dst = hdr.inner_ipv4.dst_addr;
        // Move GTPU and inner L3 headers out
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.gtpu_options.setInvalid();
        hdr.gtpu_ext_psc.setInvalid();
        fabric_md.bridged.base.gtpu_presence = GtpuPresence.NONE;
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
        if (hdr.inner_ipv4.isValid()) {
            decap_gtpu.apply();
        }
    }
}

// Allows or denies recirculation of uplink packets for UE-to-UE communication.
// Should be called after GTP decap.
control UplinkRecirc(
         inout ingress_headers_t                      hdr,
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
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_SPGW_UPLINK_RECIRC_DENY;
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
            fabric_md.lkp.ipv4_src : ternary @name("ipv4_src");
            fabric_md.lkp.ipv4_dst : ternary @name("ipv4_dst");
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
        inout ingress_headers_t                      hdr,
        inout fabric_ingress_metadata_t             fabric_md,
        /* TNA */
        in ingress_intrinsic_metadata_t             ig_intr_md,
        inout ingress_intrinsic_metadata_for_tm_t   ig_tm_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    //=============================//
    //===== Misc Things ======//
    //=============================//

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    DecapGtpu() decap_gtpu_from_dbuf;
    DecapGtpu() decap_gtpu;
    UplinkRecirc() uplink_recirc;
    bool is_pdr_hit = false;


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

    table interfaces {
        key = {
            // Outermost IPv4 header if uplink
            hdr.ipv4.dst_addr  : lpm    @name("ipv4_dst_addr");
            // gtpu extracted only if msgtype == GTPU_GPDU (see parser)
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

    action downlink_pdr_drop() {
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_DOWNLINK_PDR_MISS;
#endif // WITH_INT
    }

    action uplink_pdr_drop() {
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPLINK_PDR_MISS;
#endif // WITH_INT
    }

    // Remove after all ACE deployments will have pfcp-agent qith QoS support
    @deprecated("Use load_pdr_qos instead")
    action load_pdr(pdr_ctr_id_t    ctr_id,
                    far_id_t        far_id,
                    bool            needs_gtpu_decap) {
        fabric_md.spgw.far_id = far_id;
        fabric_md.bridged.spgw.pdr_ctr_id = ctr_id;
        fabric_md.spgw.needs_gtpu_decap = needs_gtpu_decap;
        is_pdr_hit = true;
    }

    action load_pdr_qos(pdr_ctr_id_t        ctr_id,
                        far_id_t            far_id,
                        bool                needs_gtpu_decap,
                        qid_t               qid) {
        load_pdr(ctr_id, far_id, needs_gtpu_decap);
        ig_tm_md.qid = qid;
        is_pdr_hit = true;
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
            @defaultonly downlink_pdr_drop;
        }
        size = NUM_DOWNLINK_PDRS;
        const default_action = downlink_pdr_drop();
    }

    table uplink_pdrs {
        key = {
            hdr.ipv4.dst_addr           : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid               : exact @name("teid");
        }
        actions = {
            load_pdr;
            load_pdr_qos;
            @defaultonly uplink_pdr_drop;
        }
        size = NUM_UPLINK_PDRS;
        const default_action = uplink_pdr_drop();
    }

    //=============================//
    //===== FAR Tables ======//
    //=============================//

    action far_drop() {
        // general far attributes
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        fabric_md.bridged.spgw.needs_gtpu_encap = false;
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = false;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_FAR_MISS;
#endif // WITH_INT
    }

    // FIXME: remove noticy_cp parameter, we use dbuf for DDNs.
    //   Applies to all far actions below.
    action load_normal_far(bool drop,
                           bool notify_cp) {
        // general far attributes
        fabric_md.skip_forwarding = drop;
        fabric_md.skip_next = drop;
        // Notify_spgwc is unused. We set it here to avoid the SDE optimizing
        // out the notify_cp parameter and so breaking R/W symmetry.
        fabric_md.bridged.spgw.notify_spgwc = notify_cp;
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
        // General far attributes
        fabric_md.skip_forwarding = drop;
        fabric_md.skip_next = drop;
        fabric_md.bridged.spgw.notify_spgwc = notify_cp; // Unused.
        // GTP tunnel attributes
        fabric_md.bridged.spgw.needs_gtpu_encap = true;
        fabric_md.bridged.spgw.gtpu_teid = teid;
        fabric_md.bridged.spgw.gtpu_tunnel_sport = tunnel_src_port;
        fabric_md.bridged.spgw.gtpu_tunnel_sip = tunnel_src_addr;
        fabric_md.bridged.spgw.gtpu_tunnel_dip = tunnel_dst_addr;
        fabric_md.routing_ipv4_dst = tunnel_dst_addr;
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
            @defaultonly far_drop;
        }
        // default is drop and don't notify CP
        const default_action = far_drop();
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
                if (fabric_md.spgw.src_iface == SpgwInterface.ACCESS &&
                        fabric_md.bridged.base.gtpu_presence != GtpuPresence.NONE) {
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
                if (is_pdr_hit) {
                    fars.apply();
                }

                // Recirculate UE-to-UE traffic.
                if (fabric_md.spgw.src_iface == SpgwInterface.ACCESS && fabric_md.spgw.needs_gtpu_decap) {
                    uplink_recirc.apply(hdr, fabric_md, ig_intr_md, ig_tm_md);
                }

                // Nothing to be done immediately for forwarding or encapsulation.
                // Forwarding is done by other parts of fabric.p4, and
                // encapsulation is done in the egress
            }
        }
    }
}


//====================================//
//============== Egress ==============//
//====================================//
control SpgwEgress(
        inout egress_headers_t hdr,
        inout fabric_egress_metadata_t fabric_md) {

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    @hidden
    action _encap_common() {
        // Constant fields initialized in the parser.
        hdr.outer_ipv4.setValid();
        hdr.outer_udp.setValid();
        hdr.outer_gtpu.setValid();
    }

    // Do regular GTP-U encap.
    action gtpu_only() {
        _encap_common();
        hdr.outer_ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES + GTPU_HDR_BYTES
                + hdr.ipv4.total_len;
        hdr.outer_udp.len = UDP_HDR_BYTES + GTPU_HDR_BYTES
                + hdr.ipv4.total_len;
        hdr.outer_gtpu.msglen = hdr.ipv4.total_len;
        hdr.outer_gtpu.ex_flag = 0;
#ifdef WITH_INT
        fabric_md.int_report_md.gtpu_presence = GtpuPresence.GTPU_ONLY;
#endif // WITH_INT
    }

    // Do GTP-U encap with PDU Session Container extension for 5G NG-RAN with
    // configurable QFI.
    // TODO: allow setting different QFIs in ingress
    action gtpu_with_psc(bit<6> qfi) {
        _encap_common();
        hdr.outer_ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES + GTPU_HDR_BYTES
                + GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
                + hdr.ipv4.total_len;
        hdr.outer_udp.len = UDP_HDR_BYTES + GTPU_HDR_BYTES
                + GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
                + hdr.ipv4.total_len;
        hdr.outer_gtpu.msglen = GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
                + hdr.ipv4.total_len;
        hdr.outer_gtpu.ex_flag = 1;
        hdr.outer_gtpu_options.setValid();
        hdr.outer_gtpu_ext_psc.setValid();
        hdr.outer_gtpu_ext_psc.qfi = qfi;
#ifdef WITH_INT
        fabric_md.int_report_md.gtpu_presence = GtpuPresence.GTPU_WITH_PSC;
#endif // WITH_INT
    }

    // By default, do regular GTP-U encap. Allow the control plane to enable
    // adding PDU Session Container (PSC).
    table gtpu_encap {
        actions = {
            gtpu_only;
            gtpu_with_psc;
        }
        default_action = gtpu_only();
        const size = 1;
    }

    apply {
        if (!fabric_md.bridged.spgw.skip_spgw) {
            if (fabric_md.bridged.spgw.needs_gtpu_encap) {
                gtpu_encap.apply();
            }
            if (!fabric_md.bridged.spgw.skip_egress_pdr_ctr) {
                pdr_counter.count(fabric_md.bridged.spgw.pdr_ctr_id);
            }
        }
    }
}
#endif // __SPGW__
