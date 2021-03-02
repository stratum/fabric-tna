// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

// Do not modify this file manually, use `make constants` to generate this file.

package org.stratumproject.fabric.tna.behaviour;

import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiMeterId;
import org.onosproject.net.pi.model.PiPacketMetadataId;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
/**
 * P4Info constants.
 */
public final class P4InfoConstants {

    // hide default constructor
    private P4InfoConstants() {
    }

    // Header field IDs
    public static final PiMatchFieldId HDR_BMD_TYPE =
            PiMatchFieldId.of("bmd_type");
    public static final PiMatchFieldId HDR_COPY_TO_CPU =
            PiMatchFieldId.of("copy_to_cpu");
    public static final PiMatchFieldId HDR_DROP_CTL =
            PiMatchFieldId.of("drop_ctl");
    public static final PiMatchFieldId HDR_EG_PORT =
            PiMatchFieldId.of("eg_port");
    public static final PiMatchFieldId HDR_EGRESS_PORT_SET =
            PiMatchFieldId.of("egress_port_set");
    public static final PiMatchFieldId HDR_ETH_DST =
            PiMatchFieldId.of("eth_dst");
    public static final PiMatchFieldId HDR_ETH_SRC =
            PiMatchFieldId.of("eth_src");
    public static final PiMatchFieldId HDR_ETH_TYPE =
            PiMatchFieldId.of("eth_type");
    public static final PiMatchFieldId HDR_FAR_ID = PiMatchFieldId.of("far_id");
    public static final PiMatchFieldId HDR_GTPU_IS_VALID =
            PiMatchFieldId.of("gtpu_is_valid");
    public static final PiMatchFieldId HDR_ICMP_CODE =
            PiMatchFieldId.of("icmp_code");
    public static final PiMatchFieldId HDR_ICMP_TYPE =
            PiMatchFieldId.of("icmp_type");
    public static final PiMatchFieldId HDR_IG_PORT =
            PiMatchFieldId.of("ig_port");
    public static final PiMatchFieldId HDR_INET_ADDR =
            PiMatchFieldId.of("inet_addr");
    public static final PiMatchFieldId HDR_INET_L4_PORT =
            PiMatchFieldId.of("inet_l4_port");
    public static final PiMatchFieldId HDR_INT_REPORT_TYPE =
            PiMatchFieldId.of("int_report_type");
    public static final PiMatchFieldId HDR_IP_ETH_TYPE =
            PiMatchFieldId.of("ip_eth_type");
    public static final PiMatchFieldId HDR_IP_PROTO =
            PiMatchFieldId.of("ip_proto");
    public static final PiMatchFieldId HDR_IPV4_DST =
            PiMatchFieldId.of("ipv4_dst");
    public static final PiMatchFieldId HDR_IPV4_DST_ADDR =
            PiMatchFieldId.of("ipv4_dst_addr");
    public static final PiMatchFieldId HDR_IPV4_SRC =
            PiMatchFieldId.of("ipv4_src");
    public static final PiMatchFieldId HDR_IPV6_DST =
            PiMatchFieldId.of("ipv6_dst");
    public static final PiMatchFieldId HDR_L4_DPORT =
            PiMatchFieldId.of("l4_dport");
    public static final PiMatchFieldId HDR_L4_SPORT =
            PiMatchFieldId.of("l4_sport");
    public static final PiMatchFieldId HDR_MCAST_GROUP_ID =
            PiMatchFieldId.of("mcast_group_id");
    public static final PiMatchFieldId HDR_MIRROR_TYPE =
            PiMatchFieldId.of("mirror_type");
    public static final PiMatchFieldId HDR_MPLS_LABEL =
            PiMatchFieldId.of("mpls_label");
    public static final PiMatchFieldId HDR_NEXT_ID =
            PiMatchFieldId.of("next_id");
    public static final PiMatchFieldId HDR_TEID = PiMatchFieldId.of("teid");
    public static final PiMatchFieldId HDR_TUNNEL_IPV4_DST =
            PiMatchFieldId.of("tunnel_ipv4_dst");
    public static final PiMatchFieldId HDR_UE_ADDR =
            PiMatchFieldId.of("ue_addr");
    public static final PiMatchFieldId HDR_UE_L4_PORT =
            PiMatchFieldId.of("ue_l4_port");
    public static final PiMatchFieldId HDR_VLAN_ID =
            PiMatchFieldId.of("vlan_id");
    public static final PiMatchFieldId HDR_VLAN_IS_VALID =
            PiMatchFieldId.of("vlan_is_valid");
    // Table IDs
    public static final PiTableId FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN =
            PiTableId.of("FabricEgress.egress_next.egress_vlan");
    public static final PiTableId FABRIC_EGRESS_INT_EGRESS_CONFIG =
            PiTableId.of("FabricEgress.int_egress.config");
    public static final PiTableId FABRIC_EGRESS_INT_EGRESS_INT_METADATA =
            PiTableId.of("FabricEgress.int_egress.int_metadata");
    public static final PiTableId FABRIC_EGRESS_INT_EGRESS_REPORT =
            PiTableId.of("FabricEgress.int_egress.report");
    public static final PiTableId FABRIC_EGRESS_PKT_IO_EGRESS_SWITCH_INFO =
            PiTableId.of("FabricEgress.pkt_io_egress.switch_info");
    public static final PiTableId FABRIC_INGRESS_ACL_ACL =
            PiTableId.of("FabricIngress.acl.acl");
    public static final PiTableId FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER =
            PiTableId.of("FabricIngress.filtering.fwd_classifier");
    public static final PiTableId FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN =
            PiTableId.of("FabricIngress.filtering.ingress_port_vlan");
    public static final PiTableId FABRIC_INGRESS_FORWARDING_BRIDGING =
            PiTableId.of("FabricIngress.forwarding.bridging");
    public static final PiTableId FABRIC_INGRESS_FORWARDING_MPLS =
            PiTableId.of("FabricIngress.forwarding.mpls");
    public static final PiTableId FABRIC_INGRESS_FORWARDING_ROUTING_V4 =
            PiTableId.of("FabricIngress.forwarding.routing_v4");
    public static final PiTableId FABRIC_INGRESS_FORWARDING_ROUTING_V6 =
            PiTableId.of("FabricIngress.forwarding.routing_v6");
    public static final PiTableId FABRIC_INGRESS_INT_INGRESS_DROP_REPORT =
            PiTableId.of("FabricIngress.int_ingress.drop_report");
    public static final PiTableId FABRIC_INGRESS_INT_INGRESS_WATCHLIST =
            PiTableId.of("FabricIngress.int_ingress.watchlist");
    public static final PiTableId FABRIC_INGRESS_NEXT_HASHED =
            PiTableId.of("FabricIngress.next.hashed");
    public static final PiTableId FABRIC_INGRESS_NEXT_MULTICAST =
            PiTableId.of("FabricIngress.next.multicast");
    public static final PiTableId FABRIC_INGRESS_NEXT_NEXT_VLAN =
            PiTableId.of("FabricIngress.next.next_vlan");
    public static final PiTableId FABRIC_INGRESS_SPGW_DOWNLINK_PDRS =
            PiTableId.of("FabricIngress.spgw.downlink_pdrs");
    public static final PiTableId FABRIC_INGRESS_SPGW_FARS =
            PiTableId.of("FabricIngress.spgw.fars");
    public static final PiTableId FABRIC_INGRESS_SPGW_INTERFACES =
            PiTableId.of("FabricIngress.spgw.interfaces");
    public static final PiTableId FABRIC_INGRESS_SPGW_QOS_CLASSIFIER =
            PiTableId.of("FabricIngress.spgw.qos_classifier");
    public static final PiTableId FABRIC_INGRESS_SPGW_UPLINK_PDRS =
            PiTableId.of("FabricIngress.spgw.uplink_pdrs");
    public static final PiTableId FABRIC_INGRESS_SPGW_UPLINK_RECIRC_RULES =
            PiTableId.of("FabricIngress.spgw.uplink_recirc.rules");
    // Indirect Counter IDs
    public static final PiCounterId FABRIC_EGRESS_SPGW_PDR_COUNTER =
            PiCounterId.of("FabricEgress.spgw.pdr_counter");
    public static final PiCounterId FABRIC_INGRESS_SPGW_PDR_COUNTER =
            PiCounterId.of("FabricIngress.spgw.pdr_counter");
    // Direct Counter IDs
    public static final PiCounterId FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN_COUNTER =
            PiCounterId.of("FabricEgress.egress_next.egress_vlan_counter");
    public static final PiCounterId FABRIC_INGRESS_ACL_ACL_COUNTER =
            PiCounterId.of("FabricIngress.acl.acl_counter");
    public static final PiCounterId FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER_COUNTER =
            PiCounterId.of("FabricIngress.filtering.fwd_classifier_counter");
    public static final PiCounterId FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN_COUNTER =
            PiCounterId.of("FabricIngress.filtering.ingress_port_vlan_counter");
    public static final PiCounterId FABRIC_INGRESS_FORWARDING_BRIDGING_COUNTER =
            PiCounterId.of("FabricIngress.forwarding.bridging_counter");
    public static final PiCounterId FABRIC_INGRESS_FORWARDING_MPLS_COUNTER =
            PiCounterId.of("FabricIngress.forwarding.mpls_counter");
    public static final PiCounterId FABRIC_INGRESS_NEXT_HASHED_COUNTER =
            PiCounterId.of("FabricIngress.next.hashed_counter");
    public static final PiCounterId FABRIC_INGRESS_NEXT_MULTICAST_COUNTER =
            PiCounterId.of("FabricIngress.next.multicast_counter");
    public static final PiCounterId FABRIC_INGRESS_NEXT_NEXT_VLAN_COUNTER =
            PiCounterId.of("FabricIngress.next.next_vlan_counter");
    public static final PiCounterId FABRIC_INGRESS_SPGW_UPLINK_RECIRC_RULES_COUNTER =
            PiCounterId.of("FabricIngress.spgw.uplink_recirc.rules_counter");
    // Action IDs
    public static final PiActionId FABRIC_EGRESS_EGRESS_NEXT_DROP =
            PiActionId.of("FabricEgress.egress_next.drop");
    public static final PiActionId FABRIC_EGRESS_EGRESS_NEXT_POP_VLAN =
            PiActionId.of("FabricEgress.egress_next.pop_vlan");
    public static final PiActionId FABRIC_EGRESS_EGRESS_NEXT_PUSH_VLAN =
            PiActionId.of("FabricEgress.egress_next.push_vlan");
    public static final PiActionId FABRIC_EGRESS_INT_EGRESS_DO_DROP_REPORT_ENCAP =
            PiActionId.of("FabricEgress.int_egress.do_drop_report_encap");
    public static final PiActionId FABRIC_EGRESS_INT_EGRESS_DO_DROP_REPORT_ENCAP_MPLS =
            PiActionId.of("FabricEgress.int_egress.do_drop_report_encap_mpls");
    public static final PiActionId FABRIC_EGRESS_INT_EGRESS_DO_LOCAL_REPORT_ENCAP =
            PiActionId.of("FabricEgress.int_egress.do_local_report_encap");
    public static final PiActionId FABRIC_EGRESS_INT_EGRESS_DO_LOCAL_REPORT_ENCAP_MPLS =
            PiActionId.of("FabricEgress.int_egress.do_local_report_encap_mpls");
    public static final PiActionId FABRIC_EGRESS_INT_EGRESS_REPORT_DROP =
            PiActionId.of("FabricEgress.int_egress.report_drop");
    public static final PiActionId FABRIC_EGRESS_INT_EGRESS_REPORT_LOCAL =
            PiActionId.of("FabricEgress.int_egress.report_local");
    public static final PiActionId FABRIC_EGRESS_INT_EGRESS_SET_CONFIG =
            PiActionId.of("FabricEgress.int_egress.set_config");
    public static final PiActionId FABRIC_EGRESS_PKT_IO_EGRESS_SET_SWITCH_INFO =
            PiActionId.of("FabricEgress.pkt_io_egress.set_switch_info");
    public static final PiActionId FABRIC_INGRESS_ACL_COPY_TO_CPU =
            PiActionId.of("FabricIngress.acl.copy_to_cpu");
    public static final PiActionId FABRIC_INGRESS_ACL_DROP =
            PiActionId.of("FabricIngress.acl.drop");
    public static final PiActionId FABRIC_INGRESS_ACL_NOP_ACL =
            PiActionId.of("FabricIngress.acl.nop_acl");
    public static final PiActionId FABRIC_INGRESS_ACL_PUNT_TO_CPU =
            PiActionId.of("FabricIngress.acl.punt_to_cpu");
    public static final PiActionId FABRIC_INGRESS_ACL_SET_NEXT_ID_ACL =
            PiActionId.of("FabricIngress.acl.set_next_id_acl");
    public static final PiActionId FABRIC_INGRESS_ACL_SET_OUTPUT_PORT =
            PiActionId.of("FabricIngress.acl.set_output_port");
    public static final PiActionId FABRIC_INGRESS_FILTERING_DENY =
            PiActionId.of("FabricIngress.filtering.deny");
    public static final PiActionId FABRIC_INGRESS_FILTERING_PERMIT =
            PiActionId.of("FabricIngress.filtering.permit");
    public static final PiActionId FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN =
            PiActionId.of("FabricIngress.filtering.permit_with_internal_vlan");
    public static final PiActionId FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE =
            PiActionId.of("FabricIngress.filtering.set_forwarding_type");
    public static final PiActionId FABRIC_INGRESS_FORWARDING_NOP_ROUTING_V4 =
            PiActionId.of("FabricIngress.forwarding.nop_routing_v4");
    public static final PiActionId FABRIC_INGRESS_FORWARDING_POP_MPLS_AND_NEXT =
            PiActionId.of("FabricIngress.forwarding.pop_mpls_and_next");
    public static final PiActionId FABRIC_INGRESS_FORWARDING_SET_INT_DROP_REASON =
            PiActionId.of("FabricIngress.forwarding.set_int_drop_reason");
    public static final PiActionId FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_BRIDGING =
            PiActionId.of("FabricIngress.forwarding.set_next_id_bridging");
    public static final PiActionId FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V4 =
            PiActionId.of("FabricIngress.forwarding.set_next_id_routing_v4");
    public static final PiActionId FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V6 =
            PiActionId.of("FabricIngress.forwarding.set_next_id_routing_v6");
    public static final PiActionId FABRIC_INGRESS_INT_INGRESS_MARK_TO_REPORT =
            PiActionId.of("FabricIngress.int_ingress.mark_to_report");
    public static final PiActionId FABRIC_INGRESS_INT_INGRESS_REPORT_DROP =
            PiActionId.of("FabricIngress.int_ingress.report_drop");
    public static final PiActionId FABRIC_INGRESS_NEXT_MPLS_ROUTING_HASHED =
            PiActionId.of("FabricIngress.next.mpls_routing_hashed");
    public static final PiActionId FABRIC_INGRESS_NEXT_OUTPUT_HASHED =
            PiActionId.of("FabricIngress.next.output_hashed");
    public static final PiActionId FABRIC_INGRESS_NEXT_ROUTING_HASHED =
            PiActionId.of("FabricIngress.next.routing_hashed");
    public static final PiActionId FABRIC_INGRESS_NEXT_SET_MCAST_GROUP_ID =
            PiActionId.of("FabricIngress.next.set_mcast_group_id");
    public static final PiActionId FABRIC_INGRESS_NEXT_SET_VLAN =
            PiActionId.of("FabricIngress.next.set_vlan");
    public static final PiActionId FABRIC_INGRESS_SPGW_IFACE_MISS =
            PiActionId.of("FabricIngress.spgw.iface_miss");
    public static final PiActionId FABRIC_INGRESS_SPGW_LOAD_DBUF_FAR =
            PiActionId.of("FabricIngress.spgw.load_dbuf_far");
    public static final PiActionId FABRIC_INGRESS_SPGW_LOAD_IFACE =
            PiActionId.of("FabricIngress.spgw.load_iface");
    public static final PiActionId FABRIC_INGRESS_SPGW_LOAD_NORMAL_FAR =
            PiActionId.of("FabricIngress.spgw.load_normal_far");
    public static final PiActionId FABRIC_INGRESS_SPGW_LOAD_PDR =
            PiActionId.of("FabricIngress.spgw.load_pdr");
    public static final PiActionId FABRIC_INGRESS_SPGW_LOAD_TUNNEL_FAR =
            PiActionId.of("FabricIngress.spgw.load_tunnel_far");
    public static final PiActionId FABRIC_INGRESS_SPGW_SET_QID =
            PiActionId.of("FabricIngress.spgw.set_qid");
    public static final PiActionId FABRIC_INGRESS_SPGW_UPLINK_RECIRC_ALLOW =
            PiActionId.of("FabricIngress.spgw.uplink_recirc.allow");
    public static final PiActionId FABRIC_INGRESS_SPGW_UPLINK_RECIRC_DENY =
            PiActionId.of("FabricIngress.spgw.uplink_recirc.deny");
    public static final PiActionId FABRIC_INGRESS_SPGW_UPLINK_RECIRC_MISS =
            PiActionId.of("FabricIngress.spgw.uplink_recirc.miss");
    public static final PiActionId NO_ACTION = PiActionId.of("NoAction");
    public static final PiActionId NOP = PiActionId.of("nop");
    // Action Param IDs
    public static final PiActionParamId CPU_PORT =
            PiActionParamId.of("cpu_port");
    public static final PiActionParamId CTR_ID = PiActionParamId.of("ctr_id");
    public static final PiActionParamId DMAC = PiActionParamId.of("dmac");
    public static final PiActionParamId DROP = PiActionParamId.of("drop");
    public static final PiActionParamId DROP_REASON =
            PiActionParamId.of("drop_reason");
    public static final PiActionParamId FAR_ID = PiActionParamId.of("far_id");
    public static final PiActionParamId FWD_TYPE =
            PiActionParamId.of("fwd_type");
    public static final PiActionParamId GROUP_ID =
            PiActionParamId.of("group_id");
    public static final PiActionParamId HOP_LATENCY_MASK =
            PiActionParamId.of("hop_latency_mask");
    public static final PiActionParamId LABEL = PiActionParamId.of("label");
    public static final PiActionParamId MON_IP = PiActionParamId.of("mon_ip");
    public static final PiActionParamId MON_LABEL =
            PiActionParamId.of("mon_label");
    public static final PiActionParamId MON_MAC = PiActionParamId.of("mon_mac");
    public static final PiActionParamId MON_PORT =
            PiActionParamId.of("mon_port");
    public static final PiActionParamId NEEDS_GTPU_DECAP =
            PiActionParamId.of("needs_gtpu_decap");
    public static final PiActionParamId NEXT_ID = PiActionParamId.of("next_id");
    public static final PiActionParamId NOTIFY_CP =
            PiActionParamId.of("notify_cp");
    public static final PiActionParamId PORT_NUM =
            PiActionParamId.of("port_num");
    public static final PiActionParamId QID = PiActionParamId.of("qid");
    public static final PiActionParamId SMAC = PiActionParamId.of("smac");
    public static final PiActionParamId SRC_IFACE =
            PiActionParamId.of("src_iface");
    public static final PiActionParamId SRC_IP = PiActionParamId.of("src_ip");
    public static final PiActionParamId SRC_MAC = PiActionParamId.of("src_mac");
    public static final PiActionParamId SWITCH_ID =
            PiActionParamId.of("switch_id");
    public static final PiActionParamId TEID = PiActionParamId.of("teid");
    public static final PiActionParamId TIMESTAMP_MASK =
            PiActionParamId.of("timestamp_mask");
    public static final PiActionParamId TUNNEL_DST_ADDR =
            PiActionParamId.of("tunnel_dst_addr");
    public static final PiActionParamId TUNNEL_SRC_ADDR =
            PiActionParamId.of("tunnel_src_addr");
    public static final PiActionParamId TUNNEL_SRC_PORT =
            PiActionParamId.of("tunnel_src_port");
    public static final PiActionParamId VLAN_ID = PiActionParamId.of("vlan_id");
    // Action Profile IDs
    public static final PiActionProfileId FABRIC_INGRESS_NEXT_HASHED_PROFILE =
            PiActionProfileId.of("FabricIngress.next.hashed_profile");
    // Packet Metadata IDs
    public static final PiPacketMetadataId CPU_LOOPBACK_MODE =
            PiPacketMetadataId.of("cpu_loopback_mode");
    public static final int CPU_LOOPBACK_MODE_BITWIDTH = 2;
    public static final PiPacketMetadataId EGRESS_PORT =
            PiPacketMetadataId.of("egress_port");
    public static final int EGRESS_PORT_BITWIDTH = 9;
    public static final PiPacketMetadataId ETHER_TYPE =
            PiPacketMetadataId.of("ether_type");
    public static final int ETHER_TYPE_BITWIDTH = 16;
    public static final PiPacketMetadataId INGRESS_PORT =
            PiPacketMetadataId.of("ingress_port");
    public static final int INGRESS_PORT_BITWIDTH = 9;
    public static final PiPacketMetadataId PAD0 = PiPacketMetadataId.of("pad0");
    public static final int PAD0_BITWIDTH = 85;
}
