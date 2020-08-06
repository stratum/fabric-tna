// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __INT_HEADER__
#define __INT_HEADER__

#include "define.p4"

// Report Telemetry Headers
header report_fixed_header_t {
    bit<4>  ver;
    bit<4>  nproto;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<15> rsvd;
    bit<6>  hw_id;
    bit<32> seq_no;
    bit<32> ingress_tstamp;
}

// Telemetry drop report header
header drop_report_header_t {
    bit<32> switch_id;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<8>  drop_reason;
    bit<16> pad;
}

// Switch Local Report Header
header local_report_header_t {
    bit<32> switch_id;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<24> queue_occupancy;
    bit<32> egress_tstamp;
}

header_union local_report_t {
    drop_report_header_t drop_report_header;
    local_report_header_t local_report_header;
}

header int_mirror_metadata_t {
    BridgeMetadataType bridge_md_type;
    @padding bit<6>    _pad0;
    MirrorId_t         mirror_session_id;
    bit<32>            switch_id;
    bit<16>            ingress_port_id;
    bit<16>            egress_port_id;
    bit<8>             queue_id;
    bit<24>            queue_occupancy;
    bit<32>            ingress_tstamp;
    bit<32>            egress_tstamp;
#ifdef WITH_SPGW
    bit<8>             skip_gtpu_headers;
#endif // WITH_SPGW
}

#endif
