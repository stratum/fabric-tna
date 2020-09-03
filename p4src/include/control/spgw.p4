// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __SPGW__
#define __SPGW__

control SpgwIngress(
        /* Fabric.p4 */
        inout parsed_headers_t                      hdr,
        inout fabric_ingress_metadata_t             fabric_md,
        /* TNA */
        inout ingress_intrinsic_metadata_for_tm_t   ig_tm_md) {

    //==================================//
    //===== DBuf Offload Things ======//
    //==================================//

    Register<dbuf_count_t,_>(NUM_DBUF_QUEUES) dbuf_count_register;
    RegisterAction<dbuf_count_t, _, dbuf_count_t>(dbuf_count_register) _write_dbuf_count = {
        void apply(inout dbuf_count_t value, out dbuf_count_t rv) {
            // check if the count retrieved from the packet header equals the count we have saved
            if (value == fabric_md.bridged.dbuf_packet_count)
                // if it was, the dbuf loop is empty, so send no more packets to dbuf
                value = MAX_PACKETS_TO_DBUF;
            // retval is ignored
            rv = 0;
        }
    };

    RegisterAction<dbuf_count_t, _, dbuf_count_t>(dbuf_count_register) _get_dbuf_count = {
        void apply(inout dbuf_count_t value, out dbuf_count_t rv) {
            // value = min(MAX_PACKETS_TO_DBUF, value + 1)
            if (value >= MAX_PACKETS_TO_DBUF)
                value = MAX_PACKETS_TO_DBUF;
            else
                value = value + 1;

            rv = value;
        }
    };

    RegisterAction<dbuf_count_t, _, dbuf_count_t>(dbuf_count_register) _clear_dbuf_count = {
        void apply(inout dbuf_count_t value, out dbuf_count_t rv) {
            value = 0;
            rv = 0;
        }
    };

    @hidden
    action _receive_from_dbuf() {
        fabric_md.bridged.skip_spgw = false;
        fabric_md.needs_gtpu_decap = true;
        fabric_md.from_dbuf = true;
        fabric_md.bridged.needs_dbuf = false;
        // Packets coming from dbuf will have some pipeline context saved in a GTPU extension header
        fabric_md.dbuf_queue_id = hdr.gtpu.teid;
        fabric_md.bridged.dbuf_packet_count = hdr.gtpu_ext_up4.dbuf_pkt_count;
        fabric_md.bridged.spgw_next_id = hdr.gtpu_ext_up4.next_id;
        fabric_md.bridged.pdr_ctr_id = hdr.gtpu_ext_up4.ctr_id;
        // Store the received dbuf packet count
        _write_dbuf_count.execute(fabric_md.dbuf_queue_id);
    }
    @hidden
    table receive_from_dbuf {
        key = {
            hdr.gtpu_ext_up4.isValid() : exact;
        }
        actions = {
            _receive_from_dbuf;
        }
        const entries = {
            (true) : _receive_from_dbuf();
        }
        size = 1;
    }

    //=============================//
    //===== PDR Tables ======//
    //=============================//

    action flow_lookup_miss() {
        fabric_md.bridged.skip_spgw = true;
    }

    action set_uplink_flow_attributes(pdr_ctr_id_t ctr_id,
                                      spgw_next_id_t spgw_next_id) {
            fabric_md.bridged.skip_spgw = false;
            fabric_md.bridged.needs_dbuf = false;
            fabric_md.needs_gtpu_decap = true;
            fabric_md.bridged.spgw_next_id = spgw_next_id;
            fabric_md.bridged.pdr_ctr_id = ctr_id;
    }

    action set_buffered_downlink_flow_attributes(pdr_ctr_id_t ctr_id,
                                        spgw_next_id_t spgw_next_id,
                                        dbuf_queue_id_t dbuf_queue_id) {
        fabric_md.bridged.skip_spgw = false;
        fabric_md.bridged.needs_dbuf = true;
        fabric_md.needs_gtpu_decap = false;
        fabric_md.bridged.spgw_next_id = spgw_next_id;
        fabric_md.bridged.pdr_ctr_id = ctr_id;
        fabric_md.dbuf_queue_id = dbuf_queue_id;
        fabric_md.bridged.dbuf_packet_count = _get_dbuf_count.execute(dbuf_queue_id);
    }

    // FIXME: remove dbuf_queue_id from action parameters once registers can be cleared by stratum
    action set_downlink_flow_attributes(pdr_ctr_id_t ctr_id,
                               spgw_next_id_t spgw_next_id,
                               dbuf_queue_id_t dbuf_queue_id) {
        fabric_md.bridged.skip_spgw = false;
        fabric_md.bridged.needs_dbuf = false;
        fabric_md.needs_gtpu_decap = false;
        fabric_md.bridged.spgw_next_id = spgw_next_id;
        fabric_md.bridged.pdr_ctr_id = ctr_id;
        fabric_md.dbuf_queue_id = dbuf_queue_id;
        _clear_dbuf_count.execute(dbuf_queue_id);  // workaround for control plane's inability to clear registers
    }

    table downlink_flow_lookup {
        key = {
            // only available ipv4 header
            hdr.ipv4.dst_addr : exact @name("ue_addr");
        }
        actions = {
            set_downlink_flow_attributes;
            set_buffered_downlink_flow_attributes;
            @defaultonly flow_lookup_miss;
        }
        size = MAX_DOWNLINK_SPGW_FLOWS;
        const default_action = flow_lookup_miss();
    }

    table uplink_flow_lookup {
        key = {
            hdr.ipv4.dst_addr           : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid               : exact @name("teid");
        }
        actions = {
            set_uplink_flow_attributes;
            @defaultonly flow_lookup_miss;
        }
        size = MAX_UPLINK_SPGW_FLOWS;
        const default_action = flow_lookup_miss();
    }


    //=============================//
    //======== FAR Tables =========//
    //=============================//
    @hidden
    action _correct_metadata_for_gtpu_decap() {
        // Assign these metadata fields in forwarding actions instead of in the decap table to
        // reduce spgw pipeline depth.
        // This assumes that non-tunneling forwarding will only apply to packets that arrived encapped,
        // which is *currently* a safe assumption.
        fabric_md.ipv4_src            = hdr.inner_ipv4.src_addr;
        fabric_md.ipv4_dst            = hdr.inner_ipv4.dst_addr;
        fabric_md.bridged.l4_sport    = fabric_md.bridged.innermost_l4_sport;
        fabric_md.bridged.l4_dport    = fabric_md.bridged.innermost_l4_dport;
    }

    action normal_forwarding_action() {
        _correct_metadata_for_gtpu_decap();
    }

    action dropped_forwarding_action() {
        // Do dropping in the same way as fabric's filtering.p4
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        _correct_metadata_for_gtpu_decap();
    }

    action tunneled_forwarding_action(bit<16>   tunnel_src_port,
                                      bit<32>   tunnel_src_addr,
                                      bit<32>   tunnel_dst_addr,
                                      teid_t    teid) {
        // GTP tunnel attributes
        fabric_md.bridged.needs_gtpu_encap = true;
        fabric_md.bridged.gtpu_teid = teid;
        fabric_md.bridged.gtpu_tunnel_sport = tunnel_src_port;
        fabric_md.bridged.gtpu_tunnel_sip = tunnel_src_addr;
        fabric_md.bridged.gtpu_tunnel_dip = tunnel_dst_addr;
        // update metadata for correct routing/hashing
        fabric_md.ipv4_src = tunnel_src_addr;
        fabric_md.ipv4_dst = tunnel_dst_addr;
        fabric_md.bridged.innermost_l4_sport = fabric_md.bridged.l4_sport;
        fabric_md.bridged.innermost_l4_dport = fabric_md.bridged.l4_dport;
        fabric_md.bridged.l4_sport = tunnel_src_port;
        fabric_md.bridged.l4_dport = UDP_PORT_GTPU;

    }

    table forwarding_actions {
        key = {
            fabric_md.bridged.spgw_next_id : exact @name("spgw_next_id");
        }
        actions = {
            normal_forwarding_action;
            dropped_forwarding_action;
            tunneled_forwarding_action;
        }
        // default is the average case, to reduce table size
        default_action = normal_forwarding_action();
        size = MAX_SPGW_FORWARDING_ACTIONS;
    }


    //=============================//
    //======= Misc Things =========//
    //=============================//

    action load_dbuf_tunnel_attributes(bit<32> tunnel_src_addr, bit<32> tunnel_dst_addr) {
        // Basically a normal GTPU tunnel encapsulation, but the
        // TEID stores the dbuf queue index, and in egress some metadata will be
        // preserved in a GTPU extension for the packet's return to this pipeline
        tunneled_forwarding_action(UDP_PORT_GTPU, tunnel_src_addr, tunnel_dst_addr,
                                    (teid_t) fabric_md.dbuf_queue_id);
    }

    // This is a table and not an apply block action because the 
    // tunnel source and dest addresses need to be writeable at runtime
    table redirect_to_dbuf {
        key = {
            fabric_md.bridged.needs_dbuf : exact @name("needs_dbuf");
        }
        actions = {
            load_dbuf_tunnel_attributes;
        }
        size = 1;
    }

    Counter<bit<64>, bit<16>>(MAX_PDR_COUNTERS, CounterType_t.PACKETS_AND_BYTES) pdr_counter;

    @hidden
    action decap_inner_common() {
        // Correct parser-set metadata to use the inner header values
        fabric_md.bridged.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.bridged.ip_proto    = hdr.inner_ipv4.protocol;
        // Ideally, _correct_metadata_for_gtpu_decap() would be called here, but it is called
        // by the forwarding action table instead to reduce pipeline depth
        // Move GTPU and inner L3 headers out
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.gtpu_options.setInvalid();
        hdr.gtpu_ext_up4.setInvalid();
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
        size = 4;
    }



    //=============================//
    //===== Apply Block ======//
    //=============================//
    apply {
        // Packet Detection Rule tables
        if (hdr.gtpu_ext_up4.isValid()) {
            receive_from_dbuf.apply();
        } else if (hdr.gtpu.isValid()) {
            uplink_flow_lookup.apply();
        } else {
            downlink_flow_lookup.apply();
            // Ensure metadata innermost ports are set correctly for the unencapped case.
            // Placing this in the parser is more correct but increases complexity
            fabric_md.bridged.innermost_l4_sport = fabric_md.bridged.l4_sport;
            fabric_md.bridged.innermost_l4_dport = fabric_md.bridged.l4_dport;
        }

        if (!fabric_md.bridged.skip_spgw) {
            if (!fabric_md.from_dbuf) {
                // Packets from dbuf have already been counted by ingress
                pdr_counter.count(fabric_md.bridged.pdr_ctr_id);
            }

            // Redirect to dbuf if needed and allowed, otherwise forward the packet
            if (fabric_md.bridged.needs_dbuf && 
                fabric_md.bridged.dbuf_packet_count != MAX_PACKETS_TO_DBUF) {
                redirect_to_dbuf.apply();
            } else {
                forwarding_actions.apply();
                // GTPU Decapsulate is placed after forwarding_actions to flatten a dependency
                // caused by both tables accessing hdr.inner_ipv4
                if (fabric_md.needs_gtpu_decap) {
                    decap_gtpu.apply();
                }

                // In case needs_dbuf was true but we hit MAX_PACKETS_TO_DBUF
                fabric_md.bridged.needs_dbuf = false;
            }

            /* TODO: Read fabric_md.notify_spgwc here and notify the CP, once that feature is needed*/

            // Nothing to be done immediately for forwarding or encapsulation.
            // Forwarding is done by other parts of fabric.p4, and
            // encapsulation is done in the egress
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
        hdr.outer_ipv4.src_addr = fabric_md.bridged.gtpu_tunnel_sip;
        hdr.outer_ipv4.dst_addr = fabric_md.bridged.gtpu_tunnel_dip;
        hdr.outer_ipv4.hdr_checksum = 0; // Updated later

        hdr.outer_udp.setValid();
        hdr.outer_udp.sport = fabric_md.bridged.gtpu_tunnel_sport;
        hdr.outer_udp.dport = UDP_PORT_GTPU;
        hdr.outer_udp.len = hdr.ipv4.total_len
                + (UDP_HDR_SIZE + GTP_HDR_SIZE);
        hdr.outer_udp.checksum = 0; // Updated never, due to difficulties in handling different inner headers


        hdr.outer_gtpu.setValid();
        hdr.outer_gtpu.version = GTPU_VERSION;
        hdr.outer_gtpu.pt = GTP_PROTOCOL_TYPE_GTP;
        hdr.outer_gtpu.spare = 0;
        hdr.outer_gtpu.ex_flag = 0;
        hdr.outer_gtpu.seq_flag = 0;
        hdr.outer_gtpu.npdu_flag = 0;
        hdr.outer_gtpu.msgtype = GTP_GPDU;
        hdr.outer_gtpu.msglen = hdr.ipv4.total_len;
        hdr.outer_gtpu.teid = fabric_md.bridged.gtpu_teid;
    }

    @hidden
    action save_context_for_dbuf() {
        // Add GTPU options
        hdr.outer_gtpu.ex_flag = 1; // signal that options are present
        hdr.outer_gtpu_options.setValid();
        hdr.outer_gtpu_options.next_ext = GTPU_EXT_TYPE_UP4;
        // Add our custom GTPU extension
        hdr.outer_gtpu_ext_up4.setValid();
        hdr.outer_gtpu_ext_up4.ext_len = GTPU_EXT_UP4_SIZE;
        hdr.outer_gtpu_ext_up4.dbuf_pkt_count = fabric_md.bridged.dbuf_packet_count;
        hdr.outer_gtpu_ext_up4.next_id = fabric_md.bridged.spgw_next_id;
        hdr.outer_gtpu_ext_up4.ctr_id = fabric_md.bridged.pdr_ctr_id;
        hdr.outer_gtpu_ext_up4.next_ext = 0;

        // Correct header length fields to include sizes of gtpu options and extension
        hdr.outer_udp.len = hdr.ipv4.total_len
                        + (UDP_HDR_SIZE + GTP_HDR_SIZE + GTPU_OPTIONS_SIZE + GTPU_EXT_UP4_SIZE);
        hdr.outer_ipv4.total_len = hdr.ipv4.total_len
                        + (IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_SIZE + GTPU_OPTIONS_SIZE + GTPU_EXT_UP4_SIZE);
        hdr.outer_gtpu.msglen = hdr.ipv4.total_len + (GTPU_OPTIONS_SIZE + GTPU_EXT_UP4_SIZE);
    }

    apply {

        if (fabric_md.bridged.skip_spgw) return;

        if (fabric_md.bridged.needs_gtpu_encap) {
            gtpu_encap();
            if (fabric_md.bridged.needs_dbuf) {
                save_context_for_dbuf();
            }
#ifdef WITH_INT
            fabric_md.int_mirror_md.skip_gtpu_headers = 1;
#endif // WITH_INT
        }

        if (!fabric_md.bridged.needs_dbuf) {
            // Only count packets in egress if they are not destined for an offload
            pdr_counter.count(fabric_md.bridged.pdr_ctr_id);
        } 
    }
}
#endif // __SPGW__
