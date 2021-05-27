// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __HEADER__
#define __HEADER__

#include "define.p4"


@controller_header("packet_in")
header packet_in_header_t {
    PortId_t ingress_port;
    bit<7>   _pad0;
}

// This header must have a pseudo ethertype at offset 12, to be parseable as an
// Ethernet frame in the ingress parser.
@controller_header("packet_out")
header packet_out_header_t {
    PortId_t          egress_port;
    CpuLoopbackMode_t cpu_loopback_mode;
    bit<1>            do_forwarding;
    @padding bit<84>  pad0;
    bit<16>           ether_type;
}

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
}

// NOTE: splitting the eth_type from the ethernet header helps to match on
//  the actual eth_type without checking validity bit of the VLAN tags.
header eth_type_t {
    bit<16> value;
}

header vlan_tag_t {
    bit<16> eth_type;
    bit<3> pri;
    bit<1> cfi;
    vlan_id_t vlan_id;
}

header mpls_t {
    mpls_label_t label;
    bit<3> tc;
    bit<1> bos;
    bit<8> ttl;
}

header pppoe_t {
    bit<4>  version;
    bit<4>  type_id;
    bit<8>  code;
    bit<16> session_id;
    bit<16> length;
    bit<16> protocol;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    // Not matched/modified. Treat as payload.
    // bit<32> seq_no;
    // bit<32> ack_no;
    // bit<4>  data_offset;
    // bit<3>  res;
    // bit<3>  ecn;
    // bit<6>  ctrl;
    // bit<16> window;
    // bit<16> checksum;
    // bit<16> urgent_ptr;
}

// Without @pa_container_size FabricSpgwDownlinkTest fails
// FIXME: test with future SDE releases and eventually remove pragmas
#ifdef WITH_SPGW
@pa_container_size("egress", "hdr.outer_udp.sport", 16)
@pa_container_size("egress", "hdr.outer_udp.dport", 16)
#endif // WITH_SPGW
header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    // Not matched/modified. Treat as payload.
    // bit<16> checksum;
    // Other optional fields...
}


// GTPU v1 -- 3GPP TS 29.281 version 15.7.0
// https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/15.07.00_60/ts_129281v150700p.pdf
header gtpu_t {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* whether there is an extension header optional field */
    bit<1>  seq_flag;   /* whether there is a Sequence Number optional field */
    bit<1>  npdu_flag;  /* whether there is a N-PDU number optional field */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* length of the payload in octets */
    teid_t  teid;       /* tunnel endpoint id */
}
// Follows gtpu_t if any of ex_flag, seq_flag, or npdu_flag is 1.
header gtpu_options_t {
    bit<16> seq_num;   /* Sequence number */
    bit<8>  n_pdu_num; /* N-PDU number */
    bit<8>  next_ext;  /* Next extension header */
}

// GTPU extension: PDU Session Container (PSC) -- 3GPP TS 38.415 version 15.2.0
// https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/15.02.00_60/ts_138415v150200p.pdf
header gtpu_ext_psc_t {
    bit<8> len;      /* Length in 4-octet units (common to all extensions) */
    bit<4> type;     /* Uplink or downlink */
    bit<4> spare0;   /* Reserved */
    bit<1> ppp;      /* Paging Policy Presence (UL only, not supported) */
    bit<1> rqi;      /* Reflective QoS Indicator (UL only) */
    bit<6> qfi;      /* QoS Flow Identifier */
    bit<8> next_ext;
}

@flexible
struct spgw_bridged_metadata_t {
    bool            needs_gtpu_encap;
    bool            skip_spgw;
    bool            skip_egress_pdr_ctr;
    bool            notify_spgwc;
    teid_t          gtpu_teid;
    ipv4_addr_t     gtpu_tunnel_sip;
    ipv4_addr_t     gtpu_tunnel_dip;
    l4_port_t       gtpu_tunnel_sport;
    pdr_ctr_id_t    pdr_ctr_id;
}

struct spgw_ingress_metadata_t {
    bool               needs_gtpu_decap;
    far_id_t           far_id;
    SpgwInterface      src_iface;
}


#ifdef WITH_INT
// Report Telemetry Headers v0.5
header report_fixed_header_t {
    bit<4>  ver;
    bit<4>  nproto;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<15> rsvd;
    bit<6>  hw_id;
    bit<32> seq_no;
    bit<32> ig_tstamp;
}

header common_report_header_t {
    bit<32> switch_id;
    bit<16> ig_port;
    bit<16> eg_port;
    bit<8>  queue_id;
}

// Telemetry drop report header
header drop_report_header_t {
    bit<8>  drop_reason;
    @padding bit<16> pad;
}

// Switch Local Report Header
header local_report_header_t {
    bit<24> queue_occupancy;
    bit<32> eg_tstamp;
}

// Metadata prepended to mirrored packets to generate INT reports.
// Since we don't parse the packet in the egress parser if we receive a packet
// from egress mirror, the compiler may mark the mirror metadata and other
// headers (e.g., Report headers) as "mutually exclusive". Here we set all
// fields as "no overlay" to prevent this.
@pa_no_overlay("egress", "fabric_md.int_mirror_md.bmd_type")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.mirror_type")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.ig_port")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.eg_port")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.queue_id")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.queue_occupancy")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.ig_tstamp")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.eg_tstamp")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.drop_reason")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.ip_eth_type")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.report_type")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.flow_hash")
@pa_no_overlay("egress", "fabric_md.int_mirror_md.gtpu_presence")
header int_mirror_metadata_t {
    BridgedMdType_t       bmd_type;
    @padding bit<5>       _pad0;
    FabricMirrorType_t    mirror_type;
    bit<16>               ig_port;
    bit<16>               eg_port;
    bit<8>                queue_id;
    bit<24>               queue_occupancy;
    bit<32>               ig_tstamp;
    bit<32>               eg_tstamp;
    bit<8>                drop_reason;
    bit<16>               ip_eth_type;
    GtpuPresence          gtpu_presence;
    @padding bit<4>       _pad2;
    IntReportType_t       report_type;
    flow_hash_t           flow_hash;
}

@flexible
struct int_bridged_metadata_t {
    IntReportType_t report_type;
    MirrorId_t      mirror_session_id;
}

struct int_metadata_t {
    bit<32> hop_latency;
    bit<48> timestamp;
}
#endif // WITH_INT

// Common metadata which is bridged from ingress to egress.
@flexible
struct bridged_metadata_base_t {
    flow_hash_t              inner_hash;
    mpls_label_t             mpls_label;
    PortId_t                 ig_port;
    bool                     is_multicast;
    fwd_type_t               fwd_type;
    vlan_id_t                vlan_id;
    // bit<3>                vlan_pri;
    // bit<1>                vlan_cfi;
    bit<8>                   mpls_ttl;
    bit<48>                  ig_tstamp;
    bit<16>                  ip_eth_type;
    bit<STATS_FLOW_ID_WIDTH> stats_flow_id;
    GtpuPresence             gtpu_presence;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
    bool                     push_double_vlan;
    vlan_id_t                inner_vlan_id;
    // bit<3>                inner_vlan_pri;
    // bit<1>                inner_vlan_cfi;
#endif // WITH_DOUBLE_VLAN_TERMINATION
}

header bridged_metadata_t {
    BridgedMdType_t         bmd_type;
    bridged_metadata_base_t base;
#ifdef WITH_SPGW
    spgw_bridged_metadata_t spgw;
#endif // WITH_SPGW
#ifdef WITH_INT
    int_bridged_metadata_t int_bmd;
#endif // WITH_INT
}

// Used for table lookup. Initialized with the parsed headers, or 0 if invalid
// to avoid unexpected match behavior due to PHV overlay. Never updated by the
// pipe. When both outer and inner IPv4 headers are valid, this should always
// carry the inner ones. The assumption is that we terminate GTP tunnels in the
// fabric, so we are more interested in observing/blocking the inner flows. We
// might revisit this decision in the future.
struct lookup_metadata_t {
    mac_addr_t              eth_dst;
    mac_addr_t              eth_src;
    bit<16>                 eth_type;
    vlan_id_t               vlan_id;
    bool                    is_ipv4;
    bit<32>                 ipv4_src;
    bit<32>                 ipv4_dst;
    bit<8>                  ip_proto;
    l4_port_t               l4_sport;
    l4_port_t               l4_dport;
    bit<8>                  icmp_type;
    bit<8>                  icmp_code;
}

// Ingress pipeline-only metadata
@pa_auto_init_metadata
struct fabric_ingress_metadata_t {
    bridged_metadata_t      bridged;
    flow_hash_t             ecmp_hash;
    lookup_metadata_t       lkp;
    bit<32>                 routing_ipv4_dst; // Outermost
    bool                    skip_forwarding;
    bool                    skip_next;
    next_id_t               next_id;
    bool                    egress_port_set;
    // FIXME: checksum errors are set but never read, remove or test it
    bool                    ipv4_checksum_err;
    bool                    inner_ipv4_checksum_err;
#ifdef WITH_SPGW
    spgw_ingress_metadata_t spgw;
#endif // WITH_SPGW
#ifdef WITH_INT
    int_mirror_metadata_t int_mirror_md;
#endif // WITH_INT
    PortType_t              ig_port_type;
}

// Egress pipeline-only metadata

// Common between different types of bridged metadata, used for lookup only in the egress parser.
header common_egress_metadata_t {
    BridgedMdType_t       bmd_type;
    @padding bit<5>       _pad;
    FabricMirrorType_t    mirror_type;
}

@pa_auto_init_metadata
struct fabric_egress_metadata_t {
    bridged_metadata_t    bridged;
    PortId_t              cpu_port;
#ifdef WITH_SPGW
    bool                  inner_ipv4_checksum_err;
#endif // WITH_SPGW
#ifdef WITH_INT
    int_mirror_metadata_t int_mirror_md;
    int_metadata_t        int_md;
    bit<16>               int_ipv4_len;
#endif // WITH_INT
}

header fake_ethernet_t {
    @padding bit<48> _pad0;
    @padding bit<48> _pad1;
    bit<16> ether_type;
}

struct ingress_headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    fake_ethernet_t fake_ethernet;
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
    vlan_tag_t inner_vlan_tag;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
    eth_type_t eth_type;
    mpls_t mpls;
    ipv4_t ipv4;
    ipv6_t ipv6;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    gtpu_t gtpu;
    gtpu_options_t gtpu_options;
    gtpu_ext_psc_t gtpu_ext_psc;
    ipv4_t inner_ipv4;
    tcp_t inner_tcp;
    udp_t inner_udp;
    icmp_t inner_icmp;
}

struct egress_headers_t {
    packet_in_header_t packet_in;
    fake_ethernet_t fake_ethernet;
#ifdef WITH_INT
    // INT report encapsulation.
    ethernet_t report_ethernet;
    eth_type_t report_eth_type;
    mpls_t report_mpls;
    ipv4_t report_ipv4;
    udp_t report_udp;
    report_fixed_header_t report_fixed_header;
    common_report_header_t common_report_header;
    local_report_header_t local_report_header;
    drop_report_header_t drop_report_header;
#endif // WITH_INT
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
#if defined(WITH_XCONNECT) || defined(WITH_DOUBLE_VLAN_TERMINATION)
    vlan_tag_t inner_vlan_tag;
#endif // WITH_XCONNECT || WITH_DOUBLE_VLAN_TERMINATION
    eth_type_t eth_type;
    mpls_t mpls;
#ifdef WITH_SPGW
    // GTP-U encapsulation.
    ipv4_t outer_ipv4;
    udp_t outer_udp;
    gtpu_t outer_gtpu;
    gtpu_options_t outer_gtpu_options;
    gtpu_ext_psc_t outer_gtpu_ext_psc;
#endif // WITH_SPGW
    ipv4_t ipv4;
    ipv6_t ipv6;
}

#endif // __HEADER__
