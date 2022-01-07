// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_PARSER_EMU__
#define __INT_PARSER_EMU__

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"


control IntTnaEgressParserEmulator (
    inout v1model_header_t hdr_v1model,
    inout fabric_v1model_metadata_t fabric_v1model,
    inout standard_metadata_t standard_md) {

// This control wraps all the logic defined within the TNA egress parser.
// It actually does not perform any parsing of the packet.

    egress_headers_t hdr = hdr_v1model.egress;
    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;

    @hidden
    action set_common_int_headers() {
        // Initialize report headers here to allocate constant fields on the
        /** report_ethernet **/
        hdr.report_ethernet.setValid();
        // hdr.report_ethernet.dst_addr = update later
        // hdr.report_ethernet.src_addr = update later

        /** report_eth_type **/
        hdr.report_eth_type.setValid();
        // hdr.report_eth_type.value = update later

        /** report_mpls (set valid later) **/
        // in V1model, The MPLS header is initialized in int.p4/*_encap_mpls actions,
        // because assignments made before using the setValid() have no effect.
        // hdr.report_mpls.label = update later
        // hdr.report_mpls.tc = 0;
        // hdr.report_mpls.bos = 0;
        // hdr.report_mpls.ttl = DEFAULT_MPLS_TTL;

        /** report_ipv4 **/
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4w4;
        hdr.report_ipv4.ihl = 4w5;
        hdr.report_ipv4.dscp = 0;
        hdr.report_ipv4.ecn = 2w0;
        // hdr.report_ipv4.total_len = update later
        // hdr.report_ipv4.identification = update later
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.report_ipv4.protocol = PROTO_UDP;
        // hdr.report_ipv4.hdr_checksum = update later
        // hdr.report_ipv4.src_addr = update later
        // hdr.report_ipv4.dst_addr = update later

        /** report_udp **/
        hdr.report_udp.setValid();
        hdr.report_udp.sport = 0;
        // hdr.report_udp.dport = update later
        // hdr.report_udp.len = update later
        // hdr.report_udp.checksum = update never!

        /** report_fixed_header **/
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 0;
        hdr.report_fixed_header.nproto = NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER;
        // hdr.report_fixed_header.d = update later
        // hdr.report_fixed_header.q = update later
        // hdr.report_fixed_header.f = update later
        hdr.report_fixed_header.rsvd = 0;
        // hdr.report_fixed_header.hw_id = update later
        // hdr.report_fixed_header.seq_no = update later

        /** common_report_header **/
        hdr.common_report_header.setValid();
        // hdr.common_report_header.switch_id = update later
    }

    @hidden
    action set_common_int_drop_headers() {
        set_common_int_headers();

        fabric_md.int_report_md.setValid();
        fabric_md.int_report_md.ip_eth_type = ETHERTYPE_IPV4;
        fabric_md.int_report_md.report_type = INT_REPORT_TYPE_DROP;
        fabric_md.int_report_md.mirror_type = FabricMirrorType_t.INVALID;

        /** drop_report_header **/
        hdr.drop_report_header.setValid();
        // transition set_common_int_headers;
    }

    @hidden
    action parse_int_deflected_drop() {
        set_common_int_drop_headers();

        fabric_md.int_report_md.bmd_type = BridgedMdType_t.DEFLECTED;
        fabric_md.int_report_md.encap_presence = fabric_md.bridged.base.encap_presence;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;

        /** drop_report_header **/
        hdr.drop_report_header.drop_reason = IntDropReason_t.DROP_REASON_TRAFFIC_MANAGER;
        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.bridged.base.ig_port;
        hdr.common_report_header.eg_port = fabric_md.bridged.int_bmd.egress_port;
        hdr.common_report_header.queue_id = fabric_md.bridged.int_bmd.queue_id;
    }

    @hidden
    action parse_int_ingress_drop() {
        set_common_int_drop_headers();

        fabric_md.int_report_md.bmd_type = BridgedMdType_t.INT_INGRESS_DROP;
        fabric_md.int_report_md.encap_presence = fabric_md.bridged.base.encap_presence;
        fabric_md.int_report_md.flow_hash = fabric_md.bridged.base.inner_hash;

        /** drop_report_header **/
        hdr.drop_report_header.drop_reason = fabric_md.bridged.int_bmd.drop_reason;
        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.bridged.base.ig_tstamp[31:0];
        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.bridged.base.ig_port;
        hdr.common_report_header.eg_port = 0;
        hdr.common_report_header.queue_id = 0;
    }

    @hidden
    action parse_int_report_mirror() {
        fabric_md.bridged.bmd_type = fabric_md.int_report_md.bmd_type;
        fabric_md.bridged.base.vlan_id = DEFAULT_VLAN_ID;
        fabric_md.bridged.base.mpls_label = 0; // do not push an MPLS label
        #ifdef WITH_SPGW
            fabric_md.bridged.spgw.skip_spgw = true;
        #endif // WITH_SPGW

        /** report_fixed_header **/
        hdr.report_fixed_header.ig_tstamp = fabric_md.int_report_md.ig_tstamp;

        /** common_report_header **/
        hdr.common_report_header.ig_port = fabric_md.int_report_md.ig_port;
        hdr.common_report_header.eg_port = fabric_md.int_report_md.eg_port;
        hdr.common_report_header.queue_id = fabric_md.int_report_md.queue_id;

        /** local/drop_report_header (set valid later) **/
        hdr.local_report_header.setValid();
        hdr.local_report_header.queue_occupancy = fabric_md.int_report_md.queue_occupancy;
        hdr.local_report_header.eg_tstamp = fabric_md.int_report_md.eg_tstamp;
        hdr.drop_report_header.drop_reason = fabric_md.int_report_md.drop_reason;

        // transition set_common_int_headers;
        set_common_int_headers();
    }

    apply {
        /* Deparser logic */
        // This section is needed to address various header deparsing combinations.
        // When generating the INT report, all unused headers will be stripped.

        hdr_v1model.ingress.vlan_tag.setInvalid();
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
        hdr_v1model.ingress.inner_vlan.setInvalid();
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION

        if(hdr_v1model.ingress.gtpu.isValid() || hdr_v1model.ingress.vxlan.isValid()) {
            hdr_v1model.ingress.ipv4.setInvalid();
            hdr_v1model.ingress.tcp.setInvalid();
            hdr_v1model.ingress.udp.setInvalid();
            hdr_v1model.ingress.icmp.setInvalid();

            hdr_v1model.ingress.vxlan.setInvalid();
            hdr_v1model.ingress.inner_ethernet.setInvalid();
            hdr_v1model.ingress.inner_eth_type.setInvalid();

            hdr_v1model.ingress.gtpu.setInvalid();
            hdr_v1model.ingress.gtpu_options.setInvalid();
            hdr_v1model.ingress.gtpu_ext_psc.setInvalid();

            // in case of encapsulated traffic, only inner headers are allowed.
        }

        /* End of Deparser logic */

        parse_int_ingress_drop();
        // if (IS_E2E_CLONE(standard_md)) {
             // parse_int_report_mirror(); //TODO, for egress drop reports.
        // }

        // Synch with output struct.
        hdr_v1model.egress = hdr;
        fabric_v1model.egress = fabric_md;
    }
}

#endif // __INT_PARSER_EMU__