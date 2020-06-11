// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
#ifndef __TABLE_SIZE__
#define __TABLE_SIZE__

// Default sizes when building for BMv2.
#define BNG_MAX_SUBSC 1024
#define BNG_MAX_NET_PER_SUBSC 4
#define BNG_MAX_SUBSC_NET BNG_MAX_NET_PER_SUBSC * BNG_MAX_SUBSC
#ifdef WITH_BNG
    #define PORT_VLAN_TABLE_SIZE BNG_MAX_SUBSC + 2048
#else
    #define PORT_VLAN_TABLE_SIZE 2048
#endif // WITH_BNG
#define FWD_CLASSIFIER_TABLE_SIZE 128
#define BRIDGING_TABLE_SIZE 2048
#define MPLS_TABLE_SIZE 2048
#ifdef WITH_BNG
    #define ROUTING_V4_TABLE_SIZE BNG_MAX_SUBSC_NET + 1024
#else
    #define ROUTING_V4_TABLE_SIZE 30000
#endif // WITH_BNG
#define ROUTING_V6_TABLE_SIZE 1000
#define ACL_TABLE_SIZE 2048
// Depends on number of unique next_id expected
#define NEXT_VLAN_TABLE_SIZE 2048
#define XCONNECT_NEXT_TABLE_SIZE 4096
#define SIMPLE_NEXT_TABLE_SIZE 2048
#define HASHED_NEXT_TABLE_SIZE 2048
// Max size of ECMP groups
#define HASHED_SELECTOR_MAX_GROUP_SIZE 16
// Ideally HASHED_NEXT_TABLE_SIZE * HASHED_SELECTOR_MAX_GROUP_SIZE
#define HASHED_ACT_PROFILE_SIZE 32w32768
#define MULTICAST_NEXT_TABLE_SIZE 2048
#define EGRESS_VLAN_TABLE_SIZE 2048

#endif
