// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
#ifndef __TABLE_SIZE__
#define __TABLE_SIZE__

// Default sizes when building for BMv2.
#define FWD_CLASSIFIER_TABLE_SIZE 1024
#define BRIDGING_TABLE_SIZE 1024
#define MPLS_TABLE_SIZE 1024
#define ROUTING_V4_TABLE_SIZE 1024*32*23
#define ROUTING_V6_TABLE_SIZE 1024
#define ACL_TABLE_SIZE 1024
#define XCONNECT_NEXT_TABLE_SIZE 1024
#define NEXT_VLAN_TABLE_SIZE 1024
#define SIMPLE_NEXT_TABLE_SIZE 1024
#define HASHED_NEXT_TABLE_SIZE 1024
#define HASHED_SELECTOR_MAX_GROUP_SIZE 32w16
#define HASHED_ACT_PROFILE_SIZE 32w1024
#define MULTICAST_NEXT_TABLE_SIZE 1024
#define EGRESS_VLAN_TABLE_SIZE 1024
#define PORT_VLAN_TABLE_SIZE 1024

#endif
