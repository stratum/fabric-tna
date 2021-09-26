// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __TABLE_SIZE__
#define __TABLE_SIZE__

#define PORT_VLAN_TABLE_SIZE 1024
#define FWD_CLASSIFIER_TABLE_SIZE 1024
#define BRIDGING_TABLE_SIZE 1024
#define MPLS_TABLE_SIZE 1024
#define ROUTING_V4_TABLE_SIZE 1024
#define ROUTING_V6_TABLE_SIZE 1024
#define ACL_TABLE_SIZE 1024
#define XCONNECT_NEXT_TABLE_SIZE 1024
#define NEXT_MPLS_TABLE_SIZE 1024
#define NEXT_VLAN_TABLE_SIZE 1024
#define SIMPLE_NEXT_TABLE_SIZE 1024
#define HASHED_NEXT_TABLE_SIZE 1024
#define HASHED_SELECTOR_MAX_GROUP_SIZE 32w16
#define HASHED_ACT_PROFILE_SIZE 32w1024
#define MULTICAST_NEXT_TABLE_SIZE 1024
#define EGRESS_VLAN_TABLE_SIZE 1024
#define STATS_FLOW_ID_WIDTH 10
#define SLICE_ID_WIDTH 4
#define TC_WIDTH 2
#define SLICE_TC_WIDTH (SLICE_ID_WIDTH + TC_WIDTH)
#define QOS_CLASSIFIER_TABLE_SIZE 512
#define DSCP_REWRITER_TABLE_SIZE 512

// Constants for the INT control block.
#define INT_WATCHLIST_TABLE_SIZE 64
// 4 entries per queue (for double range match on latency chunks) with up to 32 queues per port
#define INT_QUEUE_REPORT_TABLE_SIZE 32 * 4

// Constants for the SPGW control block.
#define NUM_UES 10240
// We expect between 4 and 8 tunnels per UE.
#define MAX_GTP_TUNNELS_PER_UE 1
#define NUM_GTP_TUNNLES (NUM_UES * MAX_GTP_TUNNELS_PER_UE)
// One counter for down and uplink direction.
#define MAX_PDR_COUNTERS (2 * NUM_GTP_TUNNLES)
#define NUM_UPLINK_PDRS NUM_GTP_TUNNLES
#define NUM_DOWNLINK_PDRS NUM_GTP_TUNNLES
// One table entry per down and uplink direction.
#define NUM_FARS (2 * NUM_GTP_TUNNLES)
#define NUM_SPGW_INTERFACES 64
#define NUM_QOS_CLASSES 128
#define MAX_UPLINK_RECIRC_RULES 64

#endif  //__TABLE_SIZE__
