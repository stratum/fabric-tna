// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __INT_DEFINE__
#define __INT_DEFINE__

#include <tna.p4>

/* indicate INT at LSB of DSCP */
const bit<6> INT_DSCP = 0x1;

const bit<4> NPROTO_ETHERNET = 0;
const bit<4> NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<4> NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;
const bit<16> REPORT_FIXED_HEADER_LEN = 12;
const bit<16> DROP_REPORT_HEADER_LEN = 12;
const bit<16> LOCAL_REPORT_HEADER_LEN = 16;
const bit<16> IPV4_MIN_HEAD_LEN = 20;
const bit<16> UDP_HEADER_LEN = 8;
#ifdef WITH_SPGW
const bit<16> REPORT_MIRROR_HEADER_LEN = 24;
#else
const bit<16> REPORT_MIRROR_HEADER_LEN = 23;
#endif // WITH_SPGW
const bit<16> CRC_CHECKSUM_LEN = 4;

#endif  // __INT_DEFINE__
