// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <tna.p4>

#ifndef __DEFINE__
#define __DEFINE__

#define MAX_PORTS 511

#ifndef CPU_PORT
#deinfe CPU_PORT 192
#endif

#if ! defined(WITH_SIMPLE_NEXT)
#define WITH_HASHED_NEXT
#endif

#ifndef _PKT_OUT_HDR_ANNOT
#define _PKT_OUT_HDR_ANNOT
#endif

#ifndef _PRE_INGRESS
#define _PRE_INGRESS
#endif

#ifndef _PRE_EGRESS
#define _PRE_EGRESS
#endif

#ifndef IP_VER_LENGTH
#define IP_VER_LENGTH 4
#endif
#ifndef IP_VERSION_4
#define IP_VERSION_4 4
#endif
#ifndef IP_VERSION_6
#define IP_VERSION_6 6
#endif

#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define GTP_HDR_SIZE 8
#define GTPU_OPTIONS_SIZE 4
#define GTPU_EXT_UP4_SIZE 8

#define UDP_PORT_GTPU 2152
#define GTP_GPDU 0xff
#define GTPU_VERSION 0x01
#define GTP_PROTOCOL_TYPE_GTP 0x01

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#ifndef NUM_UES
#define NUM_UES 2048
#endif

#ifndef MAX_PACKETS_TO_DBUF
#define MAX_PACKETS_TO_DBUF 1024
#endif

#ifndef NUM_DBUF_QUEUES
#define NUM_DBUF_QUEUES NUM_UES
#endif

#define MAX_PDR_COUNTERS 2*NUM_UES
#define MAX_UPLINK_SPGW_FLOWS NUM_UES
#define MAX_DOWNLINK_SPGW_FLOWS NUM_UES
#define MAX_SPGW_FORWARDING_ACTIONS 2*NUM_UES

typedef bit<3>  fwd_type_t;
typedef bit<32> next_id_t;
typedef bit<20> mpls_label_t;
typedef bit<48> mac_addr_t;
typedef bit<12> vlan_id_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;

// SPGW types
const   bit<8>  GTPU_EXT_TYPE_UP4 = 0x3f;  // two most significant bits are 0, to signal comprehension is optional
typedef bit<32> teid_t;
typedef bit<16> spgw_next_id_t;
typedef bit<16> pdr_ctr_id_t;
typedef bit<16> dbuf_count_t;  // Must be 8, 16, or 32 bits, because this will be used as a register cell type
typedef bit<32> dbuf_queue_id_t;


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

// Fake ether type used to signal that a packet is entering the pipe a second
// time because of loopback testing.
const bit<16> ETHERTYPE_LOOPBACK = 0xBF02;

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

action nop() {
    NoAction();
}

// Bridge metadata type
enum bit<8> BridgedMdType_t {
    INVALID = 0,
    // Ingress to egress.
    I2E = 1,
    // Egress to egress mirror used for INT reports.
    INT_MIRROR = 2
}

const MirrorId_t MIRROR_SESSION_ID_INVALID = 0;

// Recirculation ports for each HW pipe.
const PortId_t RECIRC_PORT_PIPE_0 = 0x44;
const PortId_t RECIRC_PORT_PIPE_1 = 0xC4;
const PortId_t RECIRC_PORT_PIPE_2 = 0x144;
const PortId_t RECIRC_PORT_PIPE_3 = 0x1C4;

#endif // __DEFINE__

