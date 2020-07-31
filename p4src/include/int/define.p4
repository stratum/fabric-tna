// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __INT_DEFINE__
#define __INT_DEFINE__

#include <tna.p4>

/* indicate INT at LSB of DSCP */
const bit<6> INT_DSCP = 0x1;

// Length of the whole INT header,
// including shim and tail, excluding metadata stack.
// 2 for int_header, 1 for shim, 1 for tail
const bit<8> INT_HEADER_LEN_WORDS = 4;
const bit<16> INT_HEADER_LEN_BYTES = 16;

const MirrorId_t REPORT_MIRROR_SESSION_ID = 7;

const bit<4> NPROTO_ETHERNET = 0;
const bit<4> NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<4> NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;

const bit<6> HW_ID = 1;
const bit<8> REPORT_FIXED_HEADER_LEN = 12;
const bit<8> DROP_REPORT_HEADER_LEN = 12;
const bit<8> LOCAL_REPORT_HEADER_LEN = 16;
const bit<8> ETH_HEADER_LEN = 14;
const bit<8> IPV4_MIN_HEAD_LEN = 20;
const bit<8> UDP_HEADER_LEN = 8;

enum bit<2> IntDeviceType {
  UNKNOWN = 0,
  SOURCE  = 1,
  TRANSIT = 2,
  SINK    = 3
}

#endif  // __INT_DEFINE__
