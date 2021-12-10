
// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __SPGW__
#define __SPGW__

#define DEFAULT_PDR_CTR_ID 0
#define DEFAULT_FAR_ID 0

control SpgwIngress(
        /* Fabric.p4 */
        inout ingress_headers_t           hdr,
        inout fabric_v1model_metadata_t   fabric_v1model,
        inout standard_metadata_t         standard_md) {

    //========================//
    //===== Misc Things ======//
    //========================//

    counter(MAX_PDR_COUNTERS, CounterType.packets_and_bytes) pdr_counter;
    // Using this local variable (fabric_md) to avoid editing all the actions, since
    // the control parameter is of type fabric_v1model_metadata_t, instead of fabric_ingress_metadata_t.
    // fabric_v1model.ingress is then updated in apply{} section, to to maintain all the edits made to fabric_md.
    fabric_ingress_metadata_t fabric_md = fabric_v1model.ingress;

    bool is_pdr_hit = false;
    far_id_t md_far_id = 0;

    @hidden
    action _gtpu_decap() {
        fabric_md.bridged.base.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.routing_ipv4_dst = hdr.inner_ipv4.dst_addr;
        // Move GTPU and inner L3 headers out
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.udp = hdr.inner_udp;
        hdr.inner_udp.setInvalid();
        hdr.tcp = hdr.inner_tcp;
        hdr.inner_tcp.setInvalid();
        hdr.icmp = hdr.inner_icmp;
        hdr.inner_icmp.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.gtpu_options.setInvalid();
        hdr.gtpu_ext_psc.setInvalid();
        fabric_md.bridged.base.encap_presence = EncapPresence.NONE;
    }


    //=============================//
    //===== Interface Tables ======//
    //=============================//

    @hidden
    action _iface_common(slice_id_t slice_id) {
        fabric_md.bridged.spgw.skip_spgw = false;
        fabric_md.is_spgw_hit = true;
        fabric_md.spgw_slice_id = slice_id;
    }

    action iface_access(slice_id_t slice_id) {
        _iface_common(slice_id);
    }

    action iface_core(slice_id_t slice_id) {
        _iface_common(slice_id);
    }

    action iface_dbuf(slice_id_t slice_id) {
        _iface_common(slice_id);
        _gtpu_decap();
    }

    action iface_miss() {
        fabric_md.bridged.spgw.skip_spgw = true;
    }

    table interfaces {
        key = {
            // Outermost IPv4 header
            hdr.ipv4.dst_addr  : lpm    @name("ipv4_dst_addr");
            // gtpu extracted only if msgtype == GTPU_GPDU (see parser)
            hdr.gtpu.isValid() : exact  @name("gtpu_is_valid");
        }
        actions = {
            iface_access;
            iface_core;
            iface_dbuf;
            @defaultonly iface_miss;
        }
        const default_action = iface_miss();
        const size = NUM_SPGW_INTERFACES;
    }

    //=======================//
    //===== PDR Tables ======//
    //=======================//

    action downlink_pdr_drop() {
        mark_to_drop(standard_md);
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_DOWNLINK_PDR_MISS;
#endif // WITH_INT
    }

    action uplink_pdr_drop() {
        mark_to_drop(standard_md);
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPLINK_PDR_MISS;
#endif // WITH_INT
    }

    action load_pdr(pdr_ctr_id_t ctr_id, far_id_t far_id, tc_t tc) {
        md_far_id = far_id;
        fabric_md.bridged.spgw.pdr_ctr_id = ctr_id;
        fabric_md.spgw_tc = tc;
        is_pdr_hit = true;
    }

    action load_pdr_decap(pdr_ctr_id_t ctr_id, far_id_t far_id, tc_t tc) {
        load_pdr(ctr_id, far_id, tc);
        _gtpu_decap();
    }

    // These two tables scale well and cover the average case PDR
    table downlink_pdrs {
        key = {
            fabric_md.routing_ipv4_dst : exact @name("ue_addr");
        }
        actions = {
            load_pdr;
            @defaultonly downlink_pdr_drop;
        }
        size = NUM_DOWNLINK_PDRS;
        const default_action = downlink_pdr_drop();
    }

    table uplink_pdrs {
        key = {
            hdr.ipv4.dst_addr : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid     : exact @name("teid");
        }
        actions = {
            load_pdr_decap;
            @defaultonly uplink_pdr_drop;
        }
        size = NUM_UPLINK_PDRS;
        const default_action = uplink_pdr_drop();
    }

    //=======================//
    //===== FAR Tables ======//
    //=======================//

    action far_drop() {
        mark_to_drop(standard_md);
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        fabric_md.bridged.spgw.needs_gtpu_encap = false;
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = false;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_FAR_MISS;
#endif // WITH_INT
    }

    action load_normal_far(BOOL drop) {
        fabric_md.skip_forwarding =(bool) drop;
        fabric_md.skip_next =(bool) drop;
        fabric_md.bridged.spgw.needs_gtpu_encap = false;
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = false;
        // FIXME: set INT drop reason if drop
    }

    // A commom part that being used for load_tunnel_far and load_dbuf_far
    @hidden
    action load_common_far(BOOL         drop,
                           l4_port_t    tunnel_src_port,
                           ipv4_addr_t  tunnel_src_addr,
                           ipv4_addr_t  tunnel_dst_addr,
                           teid_t       teid) {
        fabric_md.skip_forwarding =(bool) drop;
        fabric_md.skip_next =(bool) drop;
        // GTP tunnel attributes
        fabric_md.bridged.spgw.needs_gtpu_encap = true;
        fabric_md.bridged.spgw.gtpu_teid = teid;
        fabric_md.bridged.spgw.gtpu_tunnel_sport = tunnel_src_port;
        fabric_md.bridged.spgw.gtpu_tunnel_sip = tunnel_src_addr;
        fabric_md.bridged.spgw.gtpu_tunnel_dip = tunnel_dst_addr;
        fabric_md.routing_ipv4_dst = tunnel_dst_addr;
    }

    action load_tunnel_far(BOOL         drop,
                           l4_port_t    tunnel_src_port,
                           ipv4_addr_t  tunnel_src_addr,
                           ipv4_addr_t  tunnel_dst_addr,
                           teid_t       teid) {
        load_common_far(drop, tunnel_src_port, tunnel_src_addr,
                        tunnel_dst_addr, teid);
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = false;
    }

    action load_dbuf_far(BOOL           drop,
                         l4_port_t      tunnel_src_port,
                         ipv4_addr_t    tunnel_src_addr,
                         ipv4_addr_t    tunnel_dst_addr,
                         teid_t         teid) {
        load_common_far(drop, tunnel_src_port, tunnel_src_addr,
                        tunnel_dst_addr, teid);
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = true;
    }

    table fars {
        key = {
            md_far_id : exact @name("far_id");
        }
        actions = {
            load_normal_far;
            load_tunnel_far;
            load_dbuf_far;
            @defaultonly far_drop;
        }
        const default_action = far_drop();
        size = NUM_FARS;
    }


    //=================================//
    //===== Uplink Recirculation ======//
    //=================================//

    direct_counter(CounterType.packets) recirc_stats;

    action recirc_allow() {
        // Recirculation in bmv2 is obtained via recirculate() primitive, invoked in the egress pipeline.
        // We set the egress_spec to the ingress_port so that we can match on the egress_vlan without dropping.
        // Also, setting the egress_spec as the ingress_port lets the recirculated packet in the pipeline, by
        // matching the ingress_port_vlan.
        standard_md.egress_spec = standard_md.ingress_port;
        // Do not overwrite the vlan_id; linked to the issue mentioned above.
        fabric_v1model.do_spgw_uplink_recirc = true;
        fabric_md.egress_port_set = true;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        recirc_stats.count();
    }

    action recirc_deny() {
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_SPGW_UPLINK_RECIRC_DENY;
#endif // WITH_INT
        fabric_v1model.do_spgw_uplink_recirc = false;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        recirc_stats.count();
    }

    action recirc_miss() {
        recirc_stats.count();
    }

    // Allows or denies recirculation of uplink packets for UE-to-UE communication.
    // Should be called after GTP decap.
    table uplink_recirc_rules {
        key = {
            fabric_md.lkp.ipv4_src : ternary @name("ipv4_src");
            fabric_md.lkp.ipv4_dst : ternary @name("ipv4_dst");
        }
        actions = {
            recirc_allow;
            recirc_deny;
            @defaultonly recirc_miss;
        }
        const default_action = recirc_miss;
        size = MAX_UPLINK_RECIRC_RULES;
        counters = recirc_stats;
    }

    //========================//
    //===== Apply Block ======//
    //========================//
    apply {
        if (hdr.ipv4.isValid()) {
            switch(interfaces.apply().action_run) {
                iface_access: {
                    if (fabric_md.bridged.base.encap_presence != EncapPresence.NONE) {
                        if (uplink_pdrs.apply().hit) {
                            uplink_recirc_rules.apply();
                        }
                    }
                }
                iface_core: { downlink_pdrs.apply(); }
                iface_dbuf: { downlink_pdrs.apply(); }
            }
            if (is_pdr_hit) {
                // NOTE We should not update this counter for packets coming
                // **from** dbuf (iface_dbuf), since we already updated it when
                // first sending the same packets **to** dbuf (iface_core).
                // However, putting a condition on the iface type introduces a
                // stage dependency. We trade resource utilization with
                // accounting inaccuracy. Assuming that relatively few packets
                // can be stored at dbuf, and assuming this will be deployed
                // mostly in enterprise settings where we are not billing users,
                // the effects of such inaccuracy should be negligible.
                pdr_counter.count((bit<32>)fabric_md.bridged.spgw.pdr_ctr_id);
                fars.apply();
            }
            // Nothing to be done immediately for forwarding or encapsulation.
            // Forwarding is done by other parts of the ingress, and
            // encapsulation is done in the egress
        }

        // As last step, synchronize local var to parameter passed in control.
        fabric_v1model.ingress = fabric_md;
    }
}


//====================================//
//============== Egress ==============//
//====================================//
control SpgwEgress(
        inout ingress_headers_t hdr,
        inout fabric_v1model_metadata_t fabric_v1model) {

    counter(MAX_PDR_COUNTERS, CounterType.packets_and_bytes) pdr_counter;
    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;

    @hidden
    action _encap_initialize() {
        /** hdr.ipv4 is now outer_ipv4 **/
        hdr.ipv4.version           = 4w4;
        hdr.ipv4.ihl               = 4w5;
        hdr.ipv4.dscp              = 0;
        hdr.ipv4.ecn               = 0;
        // hdr.outer_ipv4.total_len      = update later
        hdr.ipv4.identification    = 0x1513; // From NGIC, TODO: Needs to be dynamic
        hdr.ipv4.flags             = 0;
        hdr.ipv4.frag_offset       = 0;
        hdr.ipv4.ttl               = DEFAULT_IPV4_TTL;
        hdr.ipv4.protocol          = PROTO_UDP;
        // hdr.outer_ipv4.hdr_checksum   = update later
        hdr.ipv4.src_addr          = fabric_md.bridged.spgw.gtpu_tunnel_sip;
        hdr.ipv4.dst_addr          = fabric_md.bridged.spgw.gtpu_tunnel_dip;
        /** hdr.udp is now outer_udp **/
        hdr.udp.sport              = fabric_md.bridged.spgw.gtpu_tunnel_sport;
        hdr.udp.dport              = GTPU_UDP_PORT;
        // hdr.udp.len             = update later
        // hdr.udp.checksum        = update later
        /** outer_gtpu **/
        hdr.gtpu.version           = GTP_V1;
        hdr.gtpu.pt                = GTP_PROTOCOL_TYPE_GTP;
        hdr.gtpu.spare             = 0;
        // hdr.gtpu.ex_flag        = update later
        hdr.gtpu.seq_flag          = 0;
        hdr.gtpu.npdu_flag         = 0;
        hdr.gtpu.msgtype           = GTPU_GPDU;
        // hdr.gtpu.msglen         = update later
        hdr.gtpu.teid              = fabric_md.bridged.spgw.gtpu_teid;
        /** gtpu_options **/
        hdr.gtpu_options.seq_num   = 0;
        hdr.gtpu_options.n_pdu_num = 0;
        hdr.gtpu_options.next_ext  = GTPU_NEXT_EXT_PSC;
        /** gtpu_ext_psc **/
        hdr.gtpu_ext_psc.len       = GTPU_EXT_PSC_LEN;
        hdr.gtpu_ext_psc.type      = GTPU_EXT_PSC_TYPE_DL;
        hdr.gtpu_ext_psc.spare0    = 0;
        hdr.gtpu_ext_psc.ppp       = 0;
        hdr.gtpu_ext_psc.rqi       = 0;
        // hdr.gtpu_ext_psc.qfi    = update later
        hdr.gtpu_ext_psc.next_ext  = GTPU_NEXT_EXT_NONE;
    }

    @hidden
    action _encap_common() {
        // Constant fields initialized in the parser.
        hdr.inner_ipv4.setValid();
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.udp.setValid();
        hdr.gtpu.setValid();
        // For bmv2 the initialization needs to be done after the hdr.*.setValid() is called,
        // otherwise the assignments made in _encap_initialize() have no effect.
        _encap_initialize();
    }

    // Do regular GTP-U encap.
    action gtpu_only() {
        _encap_common();
        hdr.ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES + GTPU_HDR_BYTES
                + hdr.inner_ipv4.total_len;
        hdr.udp.len = UDP_HDR_BYTES + GTPU_HDR_BYTES
                + hdr.inner_ipv4.total_len;
        hdr.gtpu.msglen = hdr.inner_ipv4.total_len;
#ifdef WITH_INT
        fabric_md.int_report_md.encap_presence = EncapPresence.GTPU_ONLY;
#endif // WITH_INT
    }

    // Do GTP-U encap with PDU Session Container extension for 5G NG-RAN with
    // configurable QFI.
    // TODO: allow setting different QFIs in ingress
    action gtpu_with_psc(bit<6> qfi) {
        // Need to set valid before assign any value, in bmv2.
        hdr.gtpu_options.setValid();
        hdr.gtpu_ext_psc.setValid();
        _encap_common();
        hdr.ipv4.total_len = IPV4_HDR_BYTES + UDP_HDR_BYTES + GTPU_HDR_BYTES
                + GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
                + hdr.inner_ipv4.total_len;
        hdr.udp.len = UDP_HDR_BYTES + GTPU_HDR_BYTES
                + GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
                + hdr.inner_ipv4.total_len;
        hdr.gtpu.msglen = GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
                + hdr.inner_ipv4.total_len;
        hdr.gtpu.ex_flag = 1;
        hdr.gtpu_ext_psc.qfi = qfi;
#ifdef WITH_INT
        fabric_md.int_report_md.encap_presence = EncapPresence.GTPU_WITH_PSC;
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
                if (hdr.udp.isValid()) {
                    hdr.inner_udp.setValid();
                    hdr.inner_udp = hdr.udp;
                    hdr.udp.setInvalid();
                }
                if (hdr.tcp.isValid()) {
                    hdr.inner_tcp.setValid();
                    hdr.inner_tcp = hdr.tcp;
                    hdr.tcp.setInvalid();
                }
                if (hdr.icmp.isValid()) {
                    hdr.inner_icmp.setValid();
                    hdr.inner_icmp = hdr.icmp;
                    hdr.icmp.setInvalid();
                }

                gtpu_encap.apply();
            }
            if (!fabric_md.bridged.spgw.skip_egress_pdr_ctr) {
                pdr_counter.count((bit<32>)fabric_md.bridged.spgw.pdr_ctr_id);
            }
        }
        fabric_v1model.egress = fabric_md;
    }
}

#endif // __SPGW__
