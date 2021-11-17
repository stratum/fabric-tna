// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __SPGW__
#define __SPGW__

#define DEFAULT_PDR_CTR_ID 0
#define DEFAULT_FAR_ID 0

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

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    // TODO: we might want to rename it as we don't use PDR abstraction anymore.
    bool is_pdr_hit = false;
    ue_session_id_t ue_session;

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

    action uplink_session_drop() {
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPLINK_UE_SESSION_MISS;
#endif // WITH_INT
    }

    action downlink_session_drop() {
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_DOWNLINK_UE_SESSION_MISS;
#endif // WITH_INT
    }

    action load_downlink_session_params(tunnel_peer_id_t tunnel_peer_id,
                                        // TODO: shouldn't we set dst tnl IP in termination table?
                                        ipv4_addr_t  tunnel_dst_addr) {
        // by using UE IP address as UE Session identifier we save PHV resources used by action.
        ue_session = fabric_md.routing_ipv4_dst;
        fabric_md.bridged.spgw.gtpu_tunnel_peer_id = tunnel_peer_id;
        fabric_md.routing_ipv4_dst = tunnel_dst_addr;
    }

    action load_uplink_session_params_decap() {
        // by using UE IP address as UE Session identifier we save PHV resources used by action.
        ue_session = fabric_md.lkp.ipv4_src;
        _gtpu_decap();
    }

    table downlink_sessions {
        key = {
            fabric_md.routing_ipv4_dst : exact @name("ue_addr");
        }
        actions = {
            load_downlink_session_params;
            @defaultonly downlink_session_drop;
        }
        size = NUM_UES;
        const default_action = downlink_session_drop();
    }

    table uplink_sessions {
        key = {
            hdr.ipv4.dst_addr : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid     : exact @name("teid");
        }
        actions = {
            load_uplink_session_params_decap;
            @defaultonly uplink_session_drop;
        }
        size = NUM_UES;
        const default_action = uplink_session_drop();
    }

    // TODO: look for better name (maybe PDRs?),
    //  but I tried to make it consistent with Figure 5.7.1.5-1 from 3GPP 23.501
    //===================================//
    //===== Per-Slice Mobile Flows ======//
    //===================================//

    action downlink_flow_drop() {
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_DOWNLINK_FLOW_MISS;
#endif // WITH_INT
    }

    action uplink_flow_drop() {
        ig_dprsr_md.drop_ctl = 1;
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
#ifdef WITH_INT
        fabric_md.bridged.int_bmd.drop_reason = IntDropReason_t.DROP_REASON_UPLINK_FLOW_MISS;
#endif // WITH_INT
    }

    action load_flow_params(pdr_ctr_id_t ctr_id,
                            tc_t tc) {
        fabric_md.bridged.spgw.pdr_ctr_id = ctr_id;
        fabric_md.spgw_tc = tc;
        is_pdr_hit = true;
    }

    action load_flow_params_encap(pdr_ctr_id_t ctr_id,
                                  tc_t         tc,
                                  teid_t       teid,
                                  // QFI should always equal 0 for 4G flows
                                  bit<6>       qfi) {
        load_flow_params(ctr_id, tc);
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = false;
        fabric_md.bridged.spgw.needs_gtpu_encap = true;
        fabric_md.bridged.spgw.gtpu_teid = teid;
        fabric_md.bridged.spgw.qfi = qfi;
        is_pdr_hit = true;
    }

    action load_flow_params_encap_dbuf(pdr_ctr_id_t ctr_id,
                                       tc_t         tc,
                                       teid_t       teid,
                                       // QFI should always equal 0 for 4G flows
                                       bit<6>       qfi) {
        load_flow_params(ctr_id, tc);
        fabric_md.bridged.spgw.needs_gtpu_encap = true;
        fabric_md.bridged.spgw.gtpu_teid = teid;
        fabric_md.bridged.spgw.qfi = qfi;
        is_pdr_hit = true;
        fabric_md.bridged.spgw.skip_egress_pdr_ctr = true;
    }

    table uplink_flows {
        key = {
            fabric_md.spgw_slice_id   : exact @name("slice_id");
            ue_session      : exact @name("ue_session");
        }

        actions = {
            load_flow_params;
            uplink_flow_drop;
        }
        const default_action = uplink_flow_drop();
        const size = NUM_MOBILE_FLOWS;
    }

    table downlink_flows {
        key = {
            fabric_md.spgw_slice_id   : exact @name("slice_id");
            ue_session      : exact @name("ue_session");
        }
        actions = {
            load_flow_params_encap;
            load_flow_params_encap_dbuf;
            downlink_flow_drop;
        }
        const default_action = downlink_flow_drop();
        const size = NUM_MOBILE_FLOWS;
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
                    if (fabric_md.bridged.base.encap_presence != EncapPresence.NONE) {
                        if (uplink_sessions.apply().hit) {
                            uplink_flows.apply();
                            uplink_recirc_rules.apply();
                        }
                    }
                }
                iface_core: {
                    if (downlink_sessions.apply().hit) {
                        downlink_flows.apply();
                    }
                }
                iface_dbuf: {
                    if (downlink_sessions.apply().hit) {
                        downlink_flows.apply();
                    }
                }
            }
            if (is_pdr_hit) {
                // NOTE We should not update this counter for packets coming
                // **from** dbuf (iface_dbuf), since we already updated it when
                // first sending the same packets **to** dbuf (iface_core).
                // However, putting a condition on the iface type introduces a
                // stage depenency. We trade resource utilization with
                // accounting inaccuracy. Assuming that relatively few packets
                // can be stored at dbuf, and assuming this will be deployed
                // mostly in enterprise settings where we are not billing users,
                // the effects of such inaccuracy should be negligible.
                pdr_counter.count(fabric_md.bridged.spgw.pdr_ctr_id);
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

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

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

    table tunnel_peers {
        key = {
            fabric_md.bridged.spgw.gtpu_tunnel_peer_id : exact @name("gtpu_tunnel_peer_id");
        }
        actions = {
            load_tunnel_params;
            nop;
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
                tunnel_peers.apply();
                gtpu_encap.apply();
            }
            if (!fabric_md.bridged.spgw.skip_egress_pdr_ctr) {
                pdr_counter.count(fabric_md.bridged.spgw.pdr_ctr_id);
            }
        }
    }
}
#endif // __SPGW__
