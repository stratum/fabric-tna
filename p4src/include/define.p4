// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <tna.p4>

#ifndef __DEFINE__
#define __DEFINE__

#if ! defined(WITH_SIMPLE_NEXT)
#define WITH_HASHED_NEXT
#endif

#define IP_VERSION_4 4
#define IP_VERSION_6 6

#define IP_VER_BITS 4
#define ETH_TYPE_BYTES 2
#define ETH_HDR_BYTES 14
#define IPV4_HDR_BYTES 20
#define IPV6_HDR_BYTES 40
#define UDP_HDR_BYTES 8
#define GTP_HDR_BYTES 8
#define MPLS_HDR_BYTES 4

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

typedef bit<3>  fwd_type_t;
typedef bit<32> next_id_t;
typedef bit<20> mpls_label_t;
typedef bit<48> mac_addr_t;
typedef bit<12> vlan_id_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;
typedef bit<32> flow_hash_t;

// SPGW types
typedef bit<32> teid_t;
typedef bit<32> far_id_t;
typedef bit<16> pdr_ctr_id_t;
enum bit<2> SpgwDirection {
    UNKNOWN             = 0x0,
    UPLINK              = 0x1,
    DOWNLINK            = 0x2,
    OTHER               = 0x3
}
enum bit<8> SpgwInterface {
    UNKNOWN       = 0x0,
    ACCESS        = 0x1,
    CORE          = 0x2,
    FROM_DBUF     = 0x3
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

// The bridged metadata type, which will make the parser understand
// the type of the metadata prepended to the packet.
enum bit<8> BridgedMdType_t {
    INVALID = 0,
    INGRESS_TO_EGRESS = 1,
    EGRESS_MIRROR = 2,
    INGRESS_MIRROR = 3
}

// The mirror type, makes the parser to use correct way to parse the mirror metadata.
// Also, lets the deparser know which type of mirroring to perform.
// The width of mirror type is same as TNA's MirrorType_t(bit<3>) so we can easily use
// it in the deparser.
enum bit<3> FabricMirrorType_t {
    INVALID = 0,
    INT_REPORT = 1
}

// Modes for CPU loopback testing, where a process can inject packets through
// the CPU port (P4RT packet-out) and expect the same to be delivered back to
// the CPU (P4RT packet-in). All modes require front-panel ports to be set in
// loopback mode.
enum bit<2> CpuLoopbackMode_t {
    // Default mode.
    DISABLED = 0,
    // Signals that the packet-out should be treated as a regular one.
    DIRECT = 1,
    // Signals that the packet-out should be processed again by the ingress
    // pipeline as if it was a packet coming from a front-panel port (defined by
    // hdr.packet_out.egress_port)
    INGRESS = 2
}

// Recirculation ports for each HW pipe.
const PortId_t RECIRC_PORT_PIPE_0 = 0x44;
const PortId_t RECIRC_PORT_PIPE_1 = 0xC4;
const PortId_t RECIRC_PORT_PIPE_2 = 0x144;
const PortId_t RECIRC_PORT_PIPE_3 = 0x1C4;

#define PIPE_0_PORTS_MATCH 9w0x000 &&& 0x180
#define PIPE_1_PORTS_MATCH 9w0x080 &&& 0x180
#define PIPE_2_PORTS_MATCH 9w0x100 &&& 0x180
#define PIPE_3_PORTS_MATCH 9w0x180 &&& 0x180

// INT

/* indicate INT at LSB of DSCP */
const bit<6> INT_DSCP = 0x1;

const bit<4>  NPROTO_ETHERNET = 0;
const bit<4>  NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<4>  NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;
const bit<16> REPORT_FIXED_HEADER_BYTES = 12;
const bit<16> DROP_REPORT_HEADER_BYTES = 12;
const bit<16> LOCAL_REPORT_HEADER_BYTES = 16;
#ifdef WITH_SPGW
const bit<16> REPORT_MIRROR_HEADER_BYTES = 31;
#else
const bit<16> REPORT_MIRROR_HEADER_BYTES = 30;
#endif // WITH_SPGW
const bit<16> ETH_FCS_LEN = 4;

const MirrorId_t REPORT_MIRROR_SESS_PIPE_0 = 300;
const MirrorId_t REPORT_MIRROR_SESS_PIPE_1 = 301;
const MirrorId_t REPORT_MIRROR_SESS_PIPE_2 = 302;
const MirrorId_t REPORT_MIRROR_SESS_PIPE_3 = 303;

#define FLOW_REPORT_FILTER_WIDTH 16
typedef bit<FLOW_REPORT_FILTER_WIDTH> flow_report_filter_index_t;
#define DROP_REPORT_FILTER_WIDTH 16
typedef bit<DROP_REPORT_FILTER_WIDTH> drop_report_filter_index_t;

enum bit<2> IntReportType_t {
    NO_REPORT = 0,
    LOCAL = 1,
    DROP = 2,
    QUEUE = 3
}

// INT drop reasons.
const bit<8> DROP_REASON_UNSET = 0;
const bit<8> DROP_REASON_UNKNOWN = 100;
const bit<8> DROP_REASON_PORT_VLAN_MAPPING_MISS = 101;
const bit<8> DROP_REASON_ACL_DENY = 102;
const bit<8> DROP_REASON_NEXT_ID_MISS = 103;
const bit<8> DROP_REASON_BRIDGING_MISS = 104;
const bit<8> DROP_REASON_MPLS_MISS = 105;
const bit<8> DROP_REASON_ROUTING_V4_MISS = 106;
const bit<8> DROP_REASON_ROUTING_V6_MISS = 107;
const bit<8> DROP_REASON_XCONNECT_MISS = 108;
const bit<8> DROP_REASON_SIMPLE_MISS = 109;
const bit<8> DROP_REASON_HASHED_MISS = 110;
const bit<8> DROP_REASON_MULTICAST_MISS = 111;
#endif // __DEFINE__
