// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include "size.p4"

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
#define ETH_FCS_BYTES 4
#define IPV4_HDR_BYTES 20
#define IPV6_HDR_BYTES 40
#define UDP_HDR_BYTES 8
#define GTPU_HDR_BYTES 8
#define GTPU_OPTIONS_HDR_BYTES 4
#define GTPU_EXT_PSC_HDR_BYTES 4
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
typedef bit<TC_WIDTH> tc_t; // Traffic Class (for QoS) whitin a slice
typedef bit<SLICE_TC_WIDTH> slice_tc_t; // Slice and TC identifier

@p4runtime_translation("tna/PortId_t", 9)
type bit<9> FabricPortId_t;

const slice_id_t DEFAULT_SLICE_ID = 0;
const tc_t DEFAULT_TC = 0;
// Check Stratum's chassis_config for other queue IDs.
// Should be the same specified in gen-qos-config.py.
const QueueId_t QUEUE_ID_BEST_EFFORT = 0;

// SPGW types
typedef bit<32> teid_t;
typedef bit<16> upf_ctr_id_t;
// We support up to 254 base stations + 1 dbuf endpoint. ID 0 is reserved.
typedef bit<8> tun_peer_id_t;
typedef bit<32> ue_session_id_t;

// According to our design choice, we report only the inner headers to the INT collector.
// The EncapPresence keeps track of the encapsulation protocol in use.
// The EncapPresence is further needed by the egress INT parser to strip out the outer encapsulation headers
// and put only inner headers in an INT report.
enum bit<2> EncapPresence {
    NONE          = 0x0,
    GTPU_ONLY     = 0x1,
    GTPU_WITH_PSC = 0x2,
    VXLAN         = 0x3
}

const bit<16> GTPU_UDP_PORT = 2152;
const bit<3> GTP_V1 = 3w1;
const bit<8> GTPU_GPDU = 0xff;
const bit<1> GTP_PROTOCOL_TYPE_GTP = 1w1;
const bit<8> GTPU_NEXT_EXT_NONE = 0x0;
const bit<8> GTPU_NEXT_EXT_PSC = 0x85;
const bit<4> GTPU_EXT_PSC_TYPE_DL = 4w0; // Downlink
const bit<4> GTPU_EXT_PSC_TYPE_UL = 4w1; // Uplink
const bit<8> GTPU_EXT_PSC_LEN = 8w1; // 1*4-octets

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

// The recirculation port uses the same number for all HW pipes. The actual port
// ID (DP_ID) can be obtained by prefixing the HW pipe ID (2 bits).
const bit<7> RECIRC_PORT_NUMBER = 7w68;

action nop() {
    NoAction();
}

// The bridged metadata type, which will make the parser understand
// the type of the metadata prepended to the packet.
enum bit<8> BridgedMdType_t {
    INVALID = 0,
    INGRESS_TO_EGRESS = 1,
    EGRESS_MIRROR = 2,
    INGRESS_MIRROR = 3,
    INT_INGRESS_DROP = 4,
    DEFLECTED = 5
}

// The mirror type, makes the parser to use correct way to parse the mirror metadata.
// Also, lets the deparser know which type of mirroring to perform.
// The width of mirror type is same as TNA's MirrorType_t(bit<3>) so we can easily use
// it in the deparser.
enum bit<3> FabricMirrorType_t {
    INVALID = 0,
    INT_REPORT = 1,
    PACKET_IN = 2
}

const MirrorId_t PACKET_IN_MIRROR_SESSION_ID = 0x1FF;

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

// INT
const bit<4>  NPROTO_ETHERNET = 0;
const bit<4>  NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<4>  NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;
const bit<16> REPORT_FIXED_HEADER_BYTES = 12;
const bit<16> DROP_REPORT_HEADER_BYTES = 12;
const bit<16> LOCAL_REPORT_HEADER_BYTES = 16;
const bit<8>  INT_MIRROR_SESSION_BASE = 0x80;
const bit<10> V1MODEL_INT_MIRROR_SESSION = 0x1FA;

#define FLOW_REPORT_FILTER_WIDTH 16
typedef bit<FLOW_REPORT_FILTER_WIDTH> flow_report_filter_index_t;
#define DROP_REPORT_FILTER_WIDTH 16
typedef bit<DROP_REPORT_FILTER_WIDTH> drop_report_filter_index_t;
#define QUEUE_REPORT_FILTER_WIDTH 12 // 7-bit of port number plus 5-bit queue id.
typedef bit<QUEUE_REPORT_FILTER_WIDTH> queue_report_filter_index_t;
typedef bit<16> queue_report_quota_t;

typedef bit<3> IntReportType_t;
const IntReportType_t INT_REPORT_TYPE_NO_REPORT = 0;
// follow the order of dqf bits in the INT fixed header
const IntReportType_t INT_REPORT_TYPE_DROP = 4;
const IntReportType_t INT_REPORT_TYPE_QUEUE = 2;
const IntReportType_t INT_REPORT_TYPE_FLOW = 1;

// Used to distinguish INT report packets generated by this switch.
// Work-in-progress because we have to complete some fields (e.g., IP and UDP length).
// 2-bit should be enough, however, the padding part for the bridge metadata
// may contain garbage values which will overlay with other fields.
typedef bit<8> IntWipType_t;
const IntWipType_t INT_IS_NOT_WIP = 0;
const IntWipType_t INT_IS_WIP = 1;
const IntWipType_t INT_IS_WIP_WITH_MPLS = 2;
// Convert values to negative value since we need to subtract length of INT headers
// from the packet length.
#ifdef V1MODEL
    const bit<16> INT_WIP_ADJUST_IP_BYTES = (ETH_HDR_BYTES - 1) ^ 0xFFFF;
#else
    const bit<16> INT_WIP_ADJUST_IP_BYTES = (ETH_HDR_BYTES + ETH_FCS_BYTES - 1) ^ 0xFFFF;
#endif // V1MODEL
const bit<16> INT_WIP_ADJUST_UDP_BYTES = INT_WIP_ADJUST_IP_BYTES - IPV4_HDR_BYTES;
const bit<16> INT_WIP_ADJUST_IP_MPLS_BYTES = INT_WIP_ADJUST_IP_BYTES - MPLS_HDR_BYTES;
const bit<16> INT_WIP_ADJUST_UDP_MPLS_BYTES = INT_WIP_ADJUST_UDP_BYTES - MPLS_HDR_BYTES;

enum bit<8> IntDropReason_t {
    // Common drop reasons
    DROP_REASON_UNKNOWN = 0,
    DROP_REASON_IP_TTL_ZERO = 26,
    DROP_REASON_ROUTING_V4_MISS = 29,
    DROP_REASON_ROUTING_V6_MISS = 29,
    DROP_REASON_PORT_VLAN_MAPPING_MISS = 55,
    DROP_REASON_TRAFFIC_MANAGER = 71,
    DROP_REASON_ACL_DENY = 80,
    DROP_REASON_BRIDGING_MISS = 89,
    // Fabric-TNA-specific drop reasons
    DROP_REASON_NEXT_ID_MISS = 128,
    DROP_REASON_MPLS_MISS = 129,
    DROP_REASON_EGRESS_NEXT_MISS = 130,
    DROP_REASON_MPLS_TTL_ZERO = 131,
    DROP_REASON_UPF_DL_SESSION_MISS = 132,
    DROP_REASON_UPF_DL_SESSION_DROP = 133,
    DROP_REASON_UPF_UL_SESSION_MISS = 134,
    DROP_REASON_UPF_UL_SESSION_DROP = 135,
    DROP_REASON_UPF_UL_SESSION_DROP_BUFF = 136,
    DROP_REASON_UPF_DL_TERMINATION_MISS = 137,
    DROP_REASON_UPF_DL_TERMINATION_DROP = 138,
    DROP_REASON_UPF_UL_TERMINATION_MISS = 139,
    DROP_REASON_UPF_UL_TERMINATION_DROP = 140,
    DROP_REASON_SPGW_UPLINK_RECIRC_DENY = 150,
    DROP_REASON_INGRESS_QOS_METER = 160,
    DROP_REASON_ROUTING_V4_DROP = 170,
    DROP_REASON_ROUTING_V6_DROP = 171
}

#endif // __DEFINE__
