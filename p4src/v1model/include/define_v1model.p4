// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

/*
    This file contains additional definitions used by bmv2.
    Extending p4src/shared/define.p4 with this file to avoid `#ifdef`s.
*/

#ifndef __DEFINE_V1MODEL__
#define __DEFINE_V1MODEL__

#ifndef WITH_LATEST_P4C //FIXME used to swtich between stable and latest p4c. Remove this ifdef and all the others when decided to use one or the other.
// remember to switch latest or stable in .env
//#define WITH_LATEST_P4C // if this is commented, stable p4c is being used.
#endif // WITH_LATEST_P4C

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

typedef bit<8> FieldListIndex_t;

const PortId_t BMV2_DROP_PORT = 511;
// The DROP_OVERRIDE_FAKE_PORT is used to override the mark_to_drop() primitive.
// Especially in INT, when dropping a packet we still want the packet to go through the egress pipeline.
// Calling mark_to_drop() will set the egress_spec = BMV2_DROP_PORT, leading to packet being dropped at the end of ingress pipeline.
// This port shouldn't be used for any other reason.
const PortId_t DROP_OVERRIDE_FAKE_PORT = 510;

// When calling recirculate/clone primitive, this index is used to inform p4c
// that standard_metadata has to be preserved in v1model_standard_md_t.
const FieldListIndex_t PRESERVE_STANDARD_MD = 255;
const FieldListIndex_t PRESERVE_FABRIC_MD = 251;
const FieldListIndex_t PRESERVE_FABRIC_MD_AND_STANDARD_MD = 250;
const FieldListIndex_t NO_PRESERVATION = 0;

#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == PKT_INSTANCE_TYPE_INGRESS_RECIRC)
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE)

#include "shared/define.p4" // Must be included AFTER defining the above typedefs.

#endif // __DEFINE_V1MODEL__
