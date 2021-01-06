// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_HEADER__
#define __INT_HEADER__

#include "define.p4"

// Report Telemetry Headers v0.5
header report_fixed_header_t {
    bit<4>  ver;
    bit<4>  nproto;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<15> rsvd;
    bit<6>  hw_id;
    bit<32> seq_no;
    bit<32> ig_tstamp;
}

header common_report_header_t {
    bit<32> switch_id;
    bit<16> ig_port;
    bit<16> eg_port;
    bit<8>  queue_id;
}

// Telemetry drop report header
header drop_report_header_t {
    bit<8>  drop_reason;
    bit<16> pad;
}

// Switch Local Report Header
header local_report_header_t {
    bit<24> queue_occupancy;
    bit<32> eg_tstamp;
}

header_union local_report_t {
    drop_report_header_t drop_report_header;
    local_report_header_t local_report_header;
}

// Since we don't parse the packet in the egress parser if
// we receive a packet from egress mirror, the compiler
// may mark the mirror metadata and other headers (e.g., IPv4)
// as "mutually exclusive".
// Here we set the mirror metadata with "no overlay" to prevent this.
@pa_no_overlay("egress", "fabric_md.int_mirror.bridge_type")
@pa_no_overlay("egress", "fabric_md.int_mirror.mirror_type")
@pa_no_overlay("egress", "fabric_md.int_mirror.mirror_session_id")
@pa_no_overlay("egress", "fabric_md.int_mirror.switch_id")
@pa_no_overlay("egress", "fabric_md.int_mirror.ig_port")
@pa_no_overlay("egress", "fabric_md.int_mirror.eg_port")
@pa_no_overlay("egress", "fabric_md.int_mirror.queue_id")
@pa_no_overlay("egress", "fabric_md.int_mirror.queue_occupancy")
@pa_no_overlay("egress", "fabric_md.int_mirror.ig_tstamp")
@pa_no_overlay("egress", "fabric_md.int_mirror.eg_tstamp")
@pa_no_overlay("egress", "fabric_md.int_mirror.ip_eth_type")
#ifdef WITH_SPGW
@pa_no_overlay("egress", "fabric_md.int_mirror.strip_gtpu")
#endif // WITH_SPGW
header int_mirror_metadata_t {
    BridgeType_t    bridge_type;
    @padding bit<5> _pad0;
    MirrorType_t    mirror_type;
    @padding bit<6> _pad1;
    MirrorId_t      mirror_session_id;
    bit<32>         switch_id;
    bit<16>         ig_port;
    bit<16>         eg_port;
    bit<8>          queue_id;
    bit<24>         queue_occupancy;
    bit<32>         ig_tstamp;
    bit<32>         eg_tstamp;
    bit<8>          drop_reason;
    bit<16>         ip_eth_type;
#ifdef WITH_SPGW
    @padding bit<7> _pad2;
    bit<1>          strip_gtpu;
#endif // WITH_SPGW
}
#endif // __INT_HEADER__
