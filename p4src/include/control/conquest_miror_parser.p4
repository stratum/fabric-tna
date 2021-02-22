// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __CONQ_MIRROR_PARSER__
#define __CONQ_MIRROR_PARSER__

parser ConqReportMirrorParser (packet_in packet,
    /* Fabric.p4 */
    out parsed_headers_t hdr,
    out fabric_egress_metadata_t fabric_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(fabric_md.conq_mirror_md);
        fabric_md.bridged.bmd_type = fabric_md.conq_mirror_md.bmd_type;
        fabric_md.bridged.vlan_id = DEFAULT_VLAN_ID;
        hdr.report_eth_type.value = ETHERTYPE_IPV4;
        hdr.eth_type.value = ETHERTYPE_CONQUEST_REPORT;
        hdr.conquest_report = {
            fabric_md.conq_mirror_md.flow_sip;
            fabric_md.conq_mirror_md.flow_dip;
            fabric_md.conq_mirror_md.flow_sport;
            fabric_md.conq_mirror_md.flow_dport;
            fabric_md.conq_mirror_md.flow_proto;
        }
    }
}
#endif // __CONQ_MIRROR_PARSER__
