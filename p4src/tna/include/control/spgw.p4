// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __SPGW__
#define __SPGW__

control SpgwIngress(
        /* Fabric.p4 */
        inout ingress_headers_t                      hdr,
        inout fabric_ingress_metadata_t             fabric_md,
        /* TNA */
        in ingress_intrinsic_metadata_t             ig_intr_md,
        inout ingress_intrinsic_metadata_for_tm_t   ig_tm_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    //========================//
    //===== Misc Things ======//
    //========================//

    Counter<bit<64>, bit<16>>(MAX_UPF_COUNTERS, CounterType_t.PACKETS_AND_BYTES) terminations_counter;

    SpgwIfaceType_t iface_type = SpgwIfaceType_t.UNKNOWN;
    bool sess_hit = false;
    bit<32> ipv4_app_addr = 0;
    l4_port_t app_port = 0;
    bit<8> proto = 0;
    bit<8> internal_app_id = DEFAULT_APP_ID;
    ue_session_id_t ue_session_id = 0;

    @hidden
    action _drop_common() {
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
    }

    @hidden
    action _term_hit(upf_ctr_id_t ctr_id) {
        fabric_md.bridged.spgw.upf_ctr_id = ctr_id;
        fabric_md.is_term_hit = true;
    }

    @hidden
    action _set_field_encap(teid_t  teid,
                            // QFI should always equal 0 for 4G flows
                            bit<6>  qfi) {
        fabric_md.bridged.spgw.needs_gtpu_encap = true;
        fabric_md.bridged.spgw.teid = teid;
        fabric_md.bridged.spgw.qfi = qfi;
    }

    @hidden
    action _gtpu_decap() {
        fabric_md.bridged.base.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.routing_ipv4_dst = hdr.inner_ipv4.dst_addr;
        // Move GTPU and inner L3 headers out
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
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

    //===============================//
    //===== UE Sessions Tables ======//
    //===============================//

    action set_uplink_session_miss() {
        _drop_common();
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_UL_SESSION_MISS;
#endif // WITH_INT
    }

    action set_uplink_session_drop() {
        sess_hit = true;
        _drop_common();
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_UL_SESSION_DROP;
#endif // WITH_INT
    }

    action set_downlink_session_miss() {
        _drop_common();
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_DL_SESSION_MISS;
#endif // WITH_INT
    }

    action set_downlink_session_drop() {
        sess_hit = true;
        _drop_common();
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_DL_SESSION_DROP;
#endif // WITH_INT
    }

    action set_downlink_session(tun_peer_id_t tun_peer_id) {
        sess_hit = true;
        // Set UE IP address.
        ue_session_id = fabric_md.routing_ipv4_dst;
        fabric_md.bridged.spgw.tun_peer_id = tun_peer_id;
        fabric_md.bridged.spgw.skip_egress_upf_ctr = false;
    }

    action set_downlink_session_buf(tun_peer_id_t tun_peer_id) {
        sess_hit = true;
        // Set UE IP address.
        ue_session_id = fabric_md.routing_ipv4_dst;
        fabric_md.bridged.spgw.tun_peer_id = tun_peer_id;
        fabric_md.bridged.spgw.skip_egress_upf_ctr = true;
    }

    action set_downlink_session_buf_drop() {
        sess_hit = true;
        // Set UE IP address, so we can match on the terminations table and
        // count packets in the ingress UPF counter.
        ue_session_id = fabric_md.routing_ipv4_dst;
        _drop_common();
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_UL_SESSION_DROP_BUFF;
#endif // WITH_INT
    }

    action set_uplink_session() {
        sess_hit = true;
        // Set UE IP address.
        ue_session_id = fabric_md.lkp.ipv4_src;
        // implicit decap
        _gtpu_decap();
    }

    table downlink_sessions {
        key = {
            fabric_md.routing_ipv4_dst : exact @name("ue_addr");
        }
        actions = {
            set_downlink_session;
            set_downlink_session_buf;
            set_downlink_session_buf_drop;
            set_downlink_session_drop;
            @defaultonly set_downlink_session_miss;
        }
        size = NUM_UES;
        const default_action = set_downlink_session_miss();
    }

    table uplink_sessions {
        key = {
            hdr.ipv4.dst_addr : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid     : exact @name("teid");
        }
        actions = {
            set_uplink_session;
            set_uplink_session_drop;
            @defaultonly set_uplink_session_miss;
        }
        size = NUM_UPLINK_SESSIONS;
        const default_action = set_uplink_session_miss();
    }

    //=============================//
    //===== UPF Terminations ======//
    //=============================//

    action uplink_drop_miss() {
        _drop_common();
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_UL_TERMINATION_MISS;
#endif // WITH_INT
    }

    action downlink_drop_miss() {
        _drop_common();
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_DL_TERMINATION_MISS;
#endif // WITH_INT
    }

    action uplink_drop(upf_ctr_id_t ctr_id) {
        _drop_common();
        _term_hit(ctr_id);
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_UL_TERMINATION_DROP;
#endif // WITH_INT
    }

    action downlink_drop(upf_ctr_id_t ctr_id) {
        _drop_common();
        _term_hit(ctr_id);
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPF_DL_TERMINATION_DROP;
#endif // WITH_INT
    }

    action app_fwd(upf_ctr_id_t ctr_id,
                   tc_t tc) {
        _term_hit(ctr_id);
        fabric_md.spgw_tc = tc;
        fabric_md.tc_unknown = false;
    }

    action app_fwd_no_tc(upf_ctr_id_t ctr_id) {
        _term_hit(ctr_id);
        fabric_md.tc_unknown = true;
    }

    action downlink_fwd_encap(upf_ctr_id_t ctr_id,
                              tc_t         tc,
                              teid_t       teid,
                              // QFI should always equal 0 for 4G flows
                              bit<6>       qfi) {
        app_fwd(ctr_id, tc);
        _set_field_encap(teid, qfi);
    }

    action downlink_fwd_encap_no_tc(upf_ctr_id_t ctr_id,
                                    teid_t       teid,
                                    // QFI should always equal 0 for 4G flows
                                    bit<6>       qfi) {
        app_fwd_no_tc(ctr_id);
        _set_field_encap(teid, qfi);
    }

    table uplink_terminations {
        key = {
            ue_session_id             : exact @name("ue_session_id");
            internal_app_id           : exact @name("app_id");
        }

        actions = {
            app_fwd;
            app_fwd_no_tc;
            uplink_drop;
            @defaultonly uplink_drop_miss;
        }
        const default_action = uplink_drop_miss();
        const size = NUM_UPF_TERMINATIONS;
    }

    table downlink_terminations {
        key = {
            ue_session_id             : exact @name("ue_session_id");
            internal_app_id           : exact @name("app_id");
        }
        actions = {
            downlink_fwd_encap;
            downlink_fwd_encap_no_tc;
            downlink_drop;
            @defaultonly downlink_drop_miss;
        }
        const default_action = downlink_drop_miss();
        const size = NUM_UPF_TERMINATIONS;
    }

    //=================================//
    //===== Ingress Tunnel Peers ======//
    //=================================//

    action set_routing_ipv4_dst(ipv4_addr_t tun_dst_addr) {
        fabric_md.routing_ipv4_dst = tun_dst_addr;
    }

    table ig_tunnel_peers {
        key = {
            fabric_md.bridged.spgw.tun_peer_id : exact @name("tun_peer_id");
        }

        actions = {
            set_routing_ipv4_dst;
            @defaultonly nop;
        }
        const default_action = nop();
        const size = MAX_GTP_TUNNEL_PEERS;
    }

    //=================================//
    //===== Application Filtering =====//
    //=================================//
    action set_app_id(bit<8> app_id) {
        internal_app_id = app_id;
    }

    table applications {
        key  = {
            fabric_md.slice_id  : exact   @name("slice_id");
            ipv4_app_addr       : lpm     @name("app_ip_address");
            app_port            : range   @name("app_l4_port");
            proto               : ternary @name("app_ip_proto");
        }
        actions = {
            set_app_id;
            @defaultonly nop;
        }
        const default_action = nop();
        size = MAX_APPLICATIONS;
    }

    //=================================//
    //===== Uplink Recirculation ======//
    //=================================//

    DirectCounter<bit<16>>(CounterType_t.PACKETS) recirc_stats;

    action recirc_allow() {
        // Pick a recirculation port within same ingress pipe to distribute load.
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port[8:7]++RECIRC_PORT_NUMBER;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.egress_port_set = true;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        recirc_stats.count();
    }

    action recirc_deny() {
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_SPGW_UPLINK_RECIRC_DENY;
#endif // WITH_INT
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
                    iface_type=SpgwIfaceType_t.ACCESS;
                    ipv4_app_addr = fabric_md.lkp.ipv4_dst;
                    app_port = fabric_md.lkp.l4_dport;
                    proto = fabric_md.lkp.ip_proto;
                    if (fabric_md.bridged.base.encap_presence != EncapPresence.NONE) {
                        uplink_sessions.apply();
                    }
                }
                iface_core: {
                    iface_type=SpgwIfaceType_t.CORE;
                    ipv4_app_addr = fabric_md.lkp.ipv4_src;
                    app_port = fabric_md.lkp.l4_sport;
                    proto = fabric_md.lkp.ip_proto;
                    downlink_sessions.apply();
                }
                iface_dbuf: {
                    iface_type=SpgwIfaceType_t.DBUF;
                    ipv4_app_addr = fabric_md.lkp.ipv4_src;
                    app_port = fabric_md.lkp.l4_sport;
                    proto = fabric_md.lkp.ip_proto;
                    downlink_sessions.apply();
                }
            }

            applications.apply();

            if (sess_hit) {
                if (iface_type == SpgwIfaceType_t.ACCESS) {
                    uplink_terminations.apply();
                    uplink_recirc_rules.apply();
                } else if (iface_type == SpgwIfaceType_t.CORE ||
                            iface_type == SpgwIfaceType_t.DBUF) {
                    downlink_terminations.apply();
                }
            }

            ig_tunnel_peers.apply();
            if (fabric_md.is_term_hit) {
                // NOTE We should not update this counter for packets coming
                // **from** dbuf (iface_dbuf), since we already updated it when
                // first sending the same packets **to** dbuf (iface_core).
                // However, putting a condition on the iface type introduces a
                // stage depenency. We trade resource utilization with
                // accounting inaccuracy. Assuming that relatively few packets
                // can be stored at dbuf, and assuming this will be deployed
                // mostly in enterprise settings where we are not billing users,
                // the effects of such inaccuracy should be negligible.
                terminations_counter.count(fabric_md.bridged.spgw.upf_ctr_id);
            }
            // Nothing to be done immediately for forwarding or encapsulation.
            // Forwarding is done by other parts of the ingress, and
            // encapsulation is done in the egress
        }
    }
}


//====================================//
//============== Egress ==============//
//====================================//
control SpgwEgress(
        inout egress_headers_t hdr,
        inout fabric_egress_metadata_t fabric_md) {

    Counter<bit<64>, bit<16>>(MAX_UPF_COUNTERS, CounterType_t.PACKETS_AND_BYTES) terminations_counter;

    //=========================//
    //===== Tunnel Peers ======//
    //=========================//

    action load_tunnel_params(l4_port_t    tunnel_src_port,
                              ipv4_addr_t  tunnel_src_addr,
                              ipv4_addr_t  tunnel_dst_addr) {
        hdr.outer_ipv4.src_addr = tunnel_src_addr;
        hdr.outer_ipv4.dst_addr = tunnel_dst_addr;
        hdr.outer_udp.sport = tunnel_src_port;
    }

    table eg_tunnel_peers {
        key = {
            fabric_md.bridged.spgw.tun_peer_id : exact @name("tun_peer_id");
        }
        actions = {
            load_tunnel_params;
            @defaultonly nop;
        }
        const default_action = nop();
        const size = MAX_GTP_TUNNEL_PEERS;
    }

    //========================//
    //===== GTP-U Encap ======//
    //========================//

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
#ifdef WITH_INT
        fabric_md.int_report_md.encap_presence = EncapPresence.GTPU_ONLY;
#endif // WITH_INT
    }

    // Do GTP-U encap with PDU Session Container extension for 5G NG-RAN with
    // configurable QFI.
    action gtpu_with_psc() {
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
        // FIXME: these fields should be intialized in the parser,
        // but due to PARSER_ERROR_MULTIWRITE the initialization is postponed.
        hdr.outer_gtpu_ext_psc.len = GTPU_EXT_PSC_LEN;
        hdr.outer_gtpu_ext_psc.rqi = 0;
        hdr.outer_gtpu_ext_psc.ppp = 0;
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
                eg_tunnel_peers.apply();
                gtpu_encap.apply();
            }
            if (!fabric_md.bridged.spgw.skip_egress_upf_ctr) {
                terminations_counter.count(fabric_md.bridged.spgw.upf_ctr_id);
            }
        }
    }
}
#endif // __SPGW__
