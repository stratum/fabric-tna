// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <v1model.p4>
#include "size.p4"

#ifndef __DEFINE__
#define __DEFINE__

#define IP_VERSION_4 4
#define IP_VERSION_6 6

#define IP_VER_BITS 4
#define ETH_TYPE_BYTES 2
#define ETH_HDR_BYTES 14
#define ETH_FCS_BYTES 4
#define IPV4_HDR_BYTES 20
#define IPV6_HDR_BYTES 40
#define UDP_HDR_BYTES 8
#define MPLS_HDR_BYTES 4
#define VLAN_HDR_BYTES 4
#define VXLAN_HDR_BYTES 8

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

typedef bit<3>  fwd_type_t;
typedef bit<32> next_id_t;
typedef bit<20> mpls_label_t;
typedef bit<48> mac_addr_t;
typedef bit<12> vlan_id_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;
typedef bit<32> flow_hash_t;
typedef bit<SLICE_ID_WIDTH> slice_id_t;
typedef bit<TC_WIDTH> tc_t; // Traffic Class (for QoS) within a slice
typedef bit<SLICE_TC_WIDTH> slice_tc_t; // Slice and TC identifier

// Start definitions from TNA (For Bmv2).
typedef bit<9>  PortId_t;           // Port id
typedef bit<16> MulticastGroupId_t; // Multicast group id
typedef bit<5>  QueueId_t;          // Queue id
typedef bit<10> MirrorId_t;         // Mirror session id
typedef bit<16> ReplicationId_t;    // Replication id
// End definitions from TNA (For Bmv2).

const slice_id_t DEFAULT_SLICE_ID = 0; 
const tc_t DEFAULT_TC = 0;
// Check Stratum's chassis_config for other queue IDs.
// Should be the same specified in gen-stratum-qos-config.py.
const QueueId_t QUEUE_ID_BEST_EFFORT = 0;


// PORT types. Set by the control plane using the actions
// of the filtering.ingress_port_vlan table.
enum bit<2> PortType_t {
    // Default value. Set by deny action.
    UNKNOWN     = 0x0,
    // Host-facing port on a leaf switch.
    EDGE        = 0x1,
    // Switch-facing port on a leaf or spine switch.
    INFRA       = 0x2,
    // ASIC-internal port such as the recirculation one (used for INT or UE-to-UE).
    INTERNAL    = 0x3
}

const bit<16> ETHERTYPE_QINQ = 0x88A8;
const bit<16> ETHERTYPE_QINQ_NON_STD = 0x9100;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_MPLS = 0x8847;
const bit<16> ETHERTYPE_MPLS_MULTICAST = 0x8848;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_PPPOED = 0x8863;
const bit<16> ETHERTYPE_PPPOES = 0x8864;
const bit<16> ETHERTYPE_PACKET_OUT = 0xBF01;

// Fake ether types used to distinguish regular packets from those used for
// CPU-based loopback testing.
const bit<16> ETHERTYPE_CPU_LOOPBACK_INGRESS = 0xBF02;
const bit<16> ETHERTYPE_CPU_LOOPBACK_EGRESS = 0xBF03;
const bit<16> ETHERTYPE_INT_WIP_IPV4 = 0xBF04;
const bit<16> ETHERTYPE_INT_WIP_MPLS = 0xBF05;

const bit<16> PPPOE_PROTOCOL_IP4 = 0x0021;
const bit<16> PPPOE_PROTOCOL_IP6 = 0x0057;
const bit<16> PPPOE_PROTOCOL_MPLS = 0x0281;

const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_ICMPV6 = 58;

const bit<4> IPV4_MIN_IHL = 5;

const fwd_type_t FWD_BRIDGING = 0;
const fwd_type_t FWD_MPLS = 1;
const fwd_type_t FWD_IPV4_UNICAST = 2;
const fwd_type_t FWD_IPV4_MULTICAST = 3;
const fwd_type_t FWD_IPV6_UNICAST = 4;
const fwd_type_t FWD_IPV6_MULTICAST = 5;
const fwd_type_t FWD_UNKNOWN = 7;

const vlan_id_t DEFAULT_VLAN_ID = 12w4094;

const bit<8> DEFAULT_MPLS_TTL = 64;
const bit<8> DEFAULT_IPV4_TTL = 64;

const bit<16> VXLAN_UDP_PORT = 4789;

action nop() {
    NoAction();
}

const MirrorId_t PACKET_IN_MIRROR_SESSION_ID = 0x210;

// Modes for CPU loopback testing, where a process can inject packets through
// the CPU port (P4RT packet-out) and expect the same to be delivered back to
// the CPU (P4RT packet-in). All modes require front-panel ports to be set in
// loopback mode.
// enum bit<2> CpuLoopbackMode_t {
//     // Default mode.
//     DISABLED = 0,
//     // Signals that the packet-out should be treated as a regular one.
//     DIRECT = 1,
//     // Signals that the packet-out should be processed again by the ingress
//     // pipeline as if it was a packet coming from a front-panel port (defined by
//     // hdr.packet_out.egress_port)
//     INGRESS = 2
// }

// Treating the CpuLoopbackMode_t as bit<2> for Bmv2. Not sure if it's feasible.
typedef bit<2> CpuLoopbackMode_t;

#endif // __DEFINE__
