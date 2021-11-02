// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

/*
    This file contains additional definitions used by bmv2.
    Extending p4src/shared/define.p4 with this file to avoid `#ifdef`s.
*/

#ifndef __DEFINE_V1MODEL__
#define __DEFINE_V1MODEL__

// Start definitions from TNA (for bmv2).
// The following typedefs are being defined
// to use the same names between the TNA and v1model versions.
// Reference to tofino.p4:
//  https://github.com/barefootnetworks/Open-Tofino/blob/master/share/p4c/p4include/tofino.p4
typedef bit<9>  PortId_t;           // Port id
typedef bit<16> MulticastGroupId_t; // Multicast group id
typedef bit<5>  QueueId_t;          // Queue id
typedef bit<10> MirrorId_t;         // Mirror session id
typedef bit<16> ReplicationId_t;    // Replication id

typedef bit<1> BOOL;

#include "shared/define.p4" // Must be included AFTER defining the above typedefs.

#endif // __DEFINE_V1MODEL__
