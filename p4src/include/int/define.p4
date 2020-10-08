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
const bit<16> REPORT_MIRROR_HEADER_LEN = 24;
const bit<16> ETH_FCS_LEN = 4;

const MirrorId_t REPORT_MIRROR_SESS_PIPE_0 = 300;
const MirrorId_t REPORT_MIRROR_SESS_PIPE_1 = 301;
const MirrorId_t REPORT_MIRROR_SESS_PIPE_2 = 302;
const MirrorId_t REPORT_MIRROR_SESS_PIPE_3 = 303;


#define PIPE_0_PORTS_MATCH 9w0x000 &&& 0x180
#define PIPE_1_PORTS_MATCH 9w0x080 &&& 0x180
#define PIPE_2_PORTS_MATCH 9w0x100 &&& 0x180
#define PIPE_3_PORTS_MATCH 9w0x180 &&& 0x180
#define WATCHLIST_TABLE_SIZE 64

#define FLOW_REPORT_FILTER_WIDTH 16
typedef bit<FLOW_REPORT_FILTER_WIDTH> flow_report_filter_index_t;

const bit<2> INT_PARSER_FLAG_STRIP_NOTHING = 0b00;
const bit<2> INT_PARSER_FLAG_STRIP_GTPU = 0b10;
const bit<2> INT_PARSER_FLAG_STRIP_MPLS = 0b01;

#endif  // __INT_DEFINE__
