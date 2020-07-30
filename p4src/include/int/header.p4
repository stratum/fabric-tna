// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __INT_HEADER__
#define __INT_HEADER__

#include "define.p4"

// INT headers - 8 bytes
header int_header_t {
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c;
    bit<1>  e;
    bit<3>  rsvd1;
    bit<5>  ins_cnt;
    bit<8>  max_hop_cnt;
    bit<8>  total_hop_cnt;
    bit<4>  instruction_mask_0003; /* split the bits for lookup */
    bit<4>  instruction_mask_0407;
    bit<4>  instruction_mask_0811;
    bit<4>  instruction_mask_1215;
    bit<16> rsvd2;
}

// INT shim header for TCP/UDP - 4 bytes
header intl4_shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len_words;
    bit<8> rsvd2;
}
// INT tail header for TCP/UDP - 4 bytes
header intl4_tail_t {
    bit<8> next_proto;
    bit<16> dest_port;
    bit<2> padding;
    bit<6> dscp;
}

header int_data_t {
    bit<32> data; // 1 word
}

#ifdef WITH_INT_TRANSIT
// INT meta-value headers - 4 bytes each
// Different header for each value type
header int_switch_id_t {
    bit<32> switch_id;
}
header int_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}
header int_hop_latency_t {
    bit<32> hop_latency;
}
header int_q_occupancy_t {
    bit<8> q_id;
    bit<24> q_occupancy;
}
header int_ingress_tstamp_t {
    bit<32> ingress_tstamp;
}
header int_egress_tstamp_t {
    bit<32> egress_tstamp;
}
header int_q_congestion_t {
    bit<8> q_id;
    bit<24> q_congestion;
}
header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}
#endif // WITH_INT_TRANSIT

#ifdef WITH_INT_SINK
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
    bit<8> len_words;
    bit<32> switch_id;
    bit<32> hop_latency;
    bit<8> q_id;
    bit<24> q_occupancy;
    bit<32> ingress_tstamp;
    bit<32> egress_tstamp;
}
#endif // WITH_INT_SINK

#endif
