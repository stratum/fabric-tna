// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __SPGW__
#define __SPGW__

#ifndef NUM_UES
#define NUM_UES 2048
#endif // NUM_UES

#ifndef MAX_BUFFERED_PACKETS
#define MAX_BUFFERED_PACKETS 1024
#endif // MAX_BUFFERED_PACKETS

#define MAX_PDR_COUNTERS 2*NUM_UES
#define NUM_UPLINK_PDRS NUM_UES
#define NUM_DOWNLINK_PDRS NUM_UES
#define NUM_FARS 2*NUM_UES

#define DEFAULT_PDR_CTR_ID 0
#define DEFAULT_FAR_ID 0

control SpgwIngress(
        /* Fabric.p4 */
        inout parsed_headers_t                      hdr,
        inout fabric_ingress_metadata_t             fabric_md,
        /* TNA */
        inout ingress_intrinsic_metadata_for_tm_t   ig_tm_md) {


    //==================================//
    //===== Buffer Offload Things ======//
    //==================================//

    Register<bit<32>,_>(NUM_FARS) buffer_count_register;

    RegisterAction<bit<32>, _, bit<32>>(buffer_count_register) _write_buffered_count = {
        void apply(inout bit<32> value, out bit<32> rv) {
            // check if the count retrieved from the packet header equals the count we have saved
            if (value == fabric_md.buffered_packet_count)
                // if it was, the buffer loop is empty, so buffer no more packets
                value = MAX_BUFFERED_PACKETS;
            // retval is ignored
            rv = 0;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(buffer_count_register) _get_buffered_count = {
        void apply(inout bit<32> value, out bit<32> rv) {
            // value = min(MAX_BUFFERED_PACKETS, value + 1)
            if (value >= MAX_BUFFERED_PACKETS)
                value = MAX_BUFFERED_PACKETS;
            else
                value = value + 1;

            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(buffer_count_register) _clear_buffered_count = {
        void apply(inout bit<32> value, out bit<32> rv) {
            value = 0;
            rv = 0;
        }
    };

    @hidden
    action _receive_from_buffer() {
        fabric_md.bridged.skip_spgw = false;
        fabric_md.from_buffer = true;
        // Packets coming from offload devices will have some context saved in repurposed header fields
        fabric_md.buffered_packet_count = hdr.gtpu.teid;
        // PDR context
        fabric_md.bridged.far_id = hdr.gtpu_options.first_short;
        fabric_md.bridged.pdr_ctr_id = hdr.gtpu_options.second_short;
        fabric_md.needs_gtpu_decap = true;
        fabric_md.bridged.needs_buffering = false;
        // Store the received buffer count
        _write_buffered_count.execute(hdr.gtpu_options.first_short);
    }
    @hidden
    table receive_from_buffer {
        key = {
            hdr.gtpu_options.isValid() : exact;
        }
        actions = {
            _receive_from_buffer;
        }
        const entries = {
            (true) : _receive_from_buffer();
        }
        size = 1;
    }


    //=============================//
    //===== PDR Tables ======//
    //=============================//

    action pdr_miss() {
        fabric_md.bridged.skip_spgw = true;
    }

    action set_pdr_buffer_attributes(pdr_ctr_id_t ctr_id,
                              far_id_t far_id,
                              bool needs_gtpu_decap) {
        fabric_md.bridged.skip_spgw = false;
        fabric_md.bridged.far_id = far_id;
        fabric_md.bridged.pdr_ctr_id = ctr_id;
        fabric_md.needs_gtpu_decap = needs_gtpu_decap;
        fabric_md.bridged.needs_buffering = true;
        fabric_md.buffered_packet_count = _get_buffered_count.execute(far_id);
    }

    action set_pdr_attributes(pdr_ctr_id_t ctr_id,
                              far_id_t far_id,
                              bool needs_gtpu_decap) {
        fabric_md.bridged.skip_spgw = false;
        fabric_md.bridged.far_id = far_id;
        fabric_md.bridged.pdr_ctr_id = ctr_id;
        fabric_md.needs_gtpu_decap = needs_gtpu_decap;
        fabric_md.bridged.needs_buffering = false;
        _clear_buffered_count.execute(far_id);
    }

    table downlink_pdr_lookup {
        key = {
            // only available ipv4 header
            hdr.ipv4.dst_addr : exact @name("ue_addr");
        }
        actions = {
            set_pdr_attributes;
            set_pdr_buffer_attributes;
            pdr_miss;
        }
        size = NUM_DOWNLINK_PDRS;
        const default_action = pdr_miss();
    }

    table uplink_pdr_lookup {
        key = {
            hdr.ipv4.dst_addr           : exact @name("tunnel_ipv4_dst");
            hdr.gtpu.teid               : exact @name("teid");
        }
        actions = {
            set_pdr_attributes;
            pdr_miss;
        }
        size = NUM_UPLINK_PDRS;
        const default_action = pdr_miss();
    }


    //=============================//
    //===== FAR Tables ======//
    //=============================//

    action load_normal_far_attributes(bool drop,
                                      bool notify_cp) {
        // Do dropping in the same way as fabric's filtering.p4
        fabric_md.skip_forwarding = drop;
        fabric_md.skip_next = drop;

        fabric_md.notify_spgwc = notify_cp; // currently does nothing
    }

    action load_tunnel_far_attributes(bool      drop,
                                      bool      notify_cp,
                                      bit<16>   tunnel_src_port,
                                      bit<32>   tunnel_src_addr,
                                      bit<32>   tunnel_dst_addr,
                                      teid_t    teid) {
        load_normal_far_attributes(drop, notify_cp);
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
            fabric_md.bridged.far_id : exact @name("far_id");
        }
        actions = {
            load_normal_far_attributes;
            load_tunnel_far_attributes;
        }
        // default is drop and don't notify CP
        const default_action = load_normal_far_attributes(true, false);
        size = NUM_FARS;
    }


    //=============================//
    //===== Misc Things ======//
    //=============================//

    action load_buffer_tunnel_attributes(bit<32> tunnel_src_addr,
                                      bit<32> tunnel_dst_addr) {
        // Basically a normal GTPU tunnel encapsulation, but the
        // TEID stores the buffered packet count, and in egress
        // some metadata will be saved in GTPU options
        load_tunnel_far_attributes(false, false, UDP_PORT_GTPU,
                                tunnel_src_addr, tunnel_dst_addr,
                                fabric_md.buffered_packet_count);
    }

    // This is a table and not an apply block action because the 
    // tunnel source and dest addresses need to be writeable at runtime
    table buffer_redirect {
        key = {
            fabric_md.bridged.needs_buffering : exact @name("needs_buffering");
        }
        actions = {
            load_buffer_tunnel_attributes;
        }
        size = 1;
    }

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
        if (hdr.gtpu_options.isValid()) {
            receive_from_buffer.apply();
        } else if (hdr.gtpu.isValid()) {
            uplink_pdr_lookup.apply();
        } else {
            downlink_pdr_lookup.apply();
        }

        if (!fabric_md.bridged.skip_spgw) {
            if (!fabric_md.from_buffer) {
                // Packets from an offload device have already been counted by ingress
                pdr_counter.count(fabric_md.bridged.pdr_ctr_id);
            }

            // GTPU Decapsulate
            if (fabric_md.needs_gtpu_decap) {
                decap_gtpu.apply();
            }

            // Redirect to a buffering device if needed and allowed,
            // or load FAR info
            if (fabric_md.bridged.needs_buffering && 
                fabric_md.buffered_packet_count != MAX_BUFFERED_PACKETS) {
                buffer_redirect.apply();
            } else {
                far_lookup.apply();
                // In case needs_buffering was true but we hit MAX_BUFFERED_PACKETS
                fabric_md.bridged.needs_buffering = false;
            }

            /* Leave out until notification feature is actually needed
            if (fabric_md.notify_spgwc) {
                // TODO: Should notification involve something other than cloning?
                // Maybe generate a digest instead?
                ig_tm_md.copy_to_cpu = 1;
            }
            */

            // Nothing to be done immediately for forwarding or encapsulation.
            // Forwarding is done by other parts of fabric.p4, and
            // encapsulation is done in the egress

            // Needed for correct GTPU encapsulation in egress
            fabric_md.bridged.spgw_ipv4_len = hdr.ipv4.total_len;
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
    action save_context_for_buffering() {
        // Packet signature was in fabric_md.bridged.gtpu_teid, so it is already saved
        // in hdr.outer_gtpu.teid
        hdr.outer_gtpu.seq_flag = 1; // signal that options are present
        hdr.outer_gtpu_options.setValid();
        hdr.outer_gtpu_options.first_short = fabric_md.bridged.far_id;
        hdr.outer_gtpu_options.second_short = fabric_md.bridged.pdr_ctr_id;
    }

    apply {

        if (fabric_md.bridged.skip_spgw) return;

        if (fabric_md.bridged.needs_gtpu_encap) {
            gtpu_encap();
            if (fabric_md.bridged.needs_buffering) {
                save_context_for_buffering();
            }
#ifdef WITH_INT
            fabric_md.int_mirror_md.skip_gtpu_headers = 1;
#endif // WITH_INT
        }

        if (!fabric_md.bridged.needs_buffering) {
            // Only count packets in egress if they are not destined for an offload
            pdr_counter.count(fabric_md.bridged.pdr_ctr_id);
        } 
    }
}
#endif // __SPGW__
