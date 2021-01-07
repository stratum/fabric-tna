// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.VlanId;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.GroupId;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowEntry;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.DefaultGroup;
import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.Group;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupKey;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiGroupKey;
import org.stratumproject.fabric.tna.behaviour.FabricUtils;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;
import org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest;

import java.util.List;
import java.util.Set;

import static org.onlab.packet.EthType.EtherType.ARP;
import static org.onlab.packet.EthType.EtherType.BDDP;
import static org.onlab.packet.EthType.EtherType.IPV4;
import static org.onlab.packet.EthType.EtherType.IPV6;
import static org.onlab.packet.EthType.EtherType.LLDP;
import static org.stratumproject.fabric.tna.behaviour.traceable.FabricTraceableMetadata.FWD_IPV4_UNICAST;
import static org.stratumproject.fabric.tna.behaviour.traceable.FabricTraceableMetadata.FWD_MPLS;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.*;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.*;

/**
 * Helper class for dataplane objects related to the Traceable tests.
 */
final class TraceableDataPlaneObjects {

    private TraceableDataPlaneObjects() {
        // Banning construction
    }

    private static final FlowRule DOWN_PORT_VLAN_FLOW = buildVlanPortRule(
            DOWN_PORT, VlanId.NONE, VlanId.NONE, HOST_VLAN_1);
    private static final FlowEntry DOWN_PORT_VLAN_FLOW_ENTRY = new DefaultFlowEntry(DOWN_PORT_VLAN_FLOW);
    private static final FlowRule UP_PORT_VLAN_FLOW = buildVlanPortRule(
            UP_PORT_1, VlanId.NONE, VlanId.NONE, DEFAULT_VLAN);
    private static final FlowEntry UP_PORT_VLAN_FLOW_ENTRY = new DefaultFlowEntry(UP_PORT_VLAN_FLOW);
    private static final FlowRule DOWN_PORT_VLAN_TAG_FLOW = buildVlanPortRule(
            DOWN_PORT_TAG, HOST_VLAN_2, VlanId.NONE, VlanId.NONE);
    private static final FlowEntry DOWN_PORT_VLAN_TAG_FLOW_ENTRY = new DefaultFlowEntry(DOWN_PORT_VLAN_TAG_FLOW);

    private static final FlowRule FWD_CLASS_IPV4_FLOW_1 = buildIPFwdClassifierRule(
            DOWN_PORT, LEAF_MAC, null, IPV4.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_1 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_1);
    private static final FlowRule FWD_CLASS_IPV4_FLOW_2 = buildIPFwdClassifierRule(
            UP_PORT_1, LEAF_MAC, null, IPV4.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_2 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_2);
    private static final FlowRule FWD_CLASS_IPV4_FLOW_3 = buildMplsFwdClassifierRule(
            UP_PORT_1, LEAF_MAC, IPV4.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_3 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_3);
    private static final FlowRule FWD_CLASS_IPV4_FLOW_4 = buildMplsFwdClassifierRule(
            UP_PORT_1, LEAF_MAC, IPV6.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_4 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_4);
    private static final FlowRule FWD_CLASS_IPV4_FLOW_5 = buildIPFwdClassifierRule(
            DOWN_PORT_TAG, LEAF_MAC, null, IPV4.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_5 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_5);

    private static final FlowRule L2_BRIDGING_FLOW = buildBridgingRule(HOST_VLAN_1, HOST_MAC, NEXT_BRIDGING, false);
    private static final FlowEntry L2_BRIDGING_FLOW_ENTRY = new DefaultFlowEntry(L2_BRIDGING_FLOW);
    private static final FlowRule L2_BROADCAST_FLOW = buildBridgingRule(HOST_VLAN_1, null, NEXT_BROADCAST, true);
    private static final FlowEntry L2_BROADCAST_FLOW_ENTRY = new DefaultFlowEntry(L2_BROADCAST_FLOW);
    private static final FlowRule L2_BROADCAST_FLOW_2 = buildBridgingRule(HOST_VLAN_2, null, NEXT_BROADCAST_2, true);
    private static final FlowEntry L2_BROADCAST_FLOW_ENTRY_2 = new DefaultFlowEntry(L2_BROADCAST_FLOW_2);

    private static final FlowRule IPV4_ROUTING_FLOW = buildIPv4RoutingRule(HOST_IPV4, NEXT_ROUTING);
    private static final FlowEntry IPV4_ROUTING_FLOW_ENTRY = new DefaultFlowEntry(IPV4_ROUTING_FLOW);
    private static final FlowRule DEFAULT_IPV4_ROUTING_FLOW = buildIPv4RoutingRule(DEFAULT_IPV4, NEXT_ECMP);
    private static final FlowEntry DEFAULT_IPV4_ROUTING_FLOW_ENTRY = new DefaultFlowEntry(DEFAULT_IPV4_ROUTING_FLOW);
    private static final FlowRule SUBNET_IPV4_ROUTING_FLOW = buildIPv4RoutingRule(SUBNET_IPV4, NEXT_ECMP);
    private static final FlowEntry SUBNET_IPV4_ROUTING_FLOW_ENTRY = new DefaultFlowEntry(SUBNET_IPV4_ROUTING_FLOW);

    private static final FlowRule MPLS_FLOW = buildMplsRule(MPLS_LABEL, NEXT_MPLS);
    private static final FlowEntry MPLS_FLOW_ENTRY = new DefaultFlowEntry(MPLS_FLOW);

    private static final FlowRule PUNT_IP_ACL_FLOW = buildPuntIpAclRule(IPV4.ethType().toShort(), PUNT_IPV4);
    private static final FlowEntry PUNT_IP_ACL_FLOW_ENTRY = new DefaultFlowEntry(PUNT_IP_ACL_FLOW);
    private static final FlowRule ARP_ACL_FLOW = buildArpAclRule();
    private static final FlowEntry ARP_ACL_FLOW_ENTRY = new DefaultFlowEntry(ARP_ACL_FLOW);
    private static final FlowRule PUNT_LLDP_ACL_FLOW = buildPuntEthTypeAclRule(LLDP.ethType().toShort());
    private static final FlowEntry PUNT_LLDP_ACL_FLOW_ENTRY = new DefaultFlowEntry(PUNT_LLDP_ACL_FLOW);
    private static final FlowRule PUNT_BDDP_ACL_FLOW = buildPuntEthTypeAclRule(BDDP.ethType().toShort());
    private static final FlowEntry PUNT_BDDP_ACL_FLOW_ENTRY = new DefaultFlowEntry(PUNT_BDDP_ACL_FLOW);
    private static final FlowRule PUNT_IP_ACL_FLOW_1 = buildPuntIpAclRule(IPV4.ethType().toShort(), PUNT_IPV4_TAG);
    private static final FlowEntry PUNT_IP_ACL_FLOW_ENTRY_1 = new DefaultFlowEntry(PUNT_IP_ACL_FLOW_1);

    private static final FlowRule NEXT_VLAN_FLOW_1 = buildNextVlanRule(NEXT_BRIDGING, HOST_VLAN_1);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_1 = new DefaultFlowEntry(NEXT_VLAN_FLOW_1);
    private static final FlowRule NEXT_VLAN_FLOW_2 = buildNextVlanRule(NEXT_ROUTING, HOST_VLAN_1);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_2 = new DefaultFlowEntry(NEXT_VLAN_FLOW_2);
    private static final FlowRule NEXT_VLAN_FLOW_3 = buildNextVlanRule(NEXT_MPLS, DEFAULT_VLAN);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_3 = new DefaultFlowEntry(NEXT_VLAN_FLOW_3);
    private static final FlowRule NEXT_VLAN_FLOW_4 = buildNextVlanRule(NEXT_BROADCAST, HOST_VLAN_1);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_4 = new DefaultFlowEntry(NEXT_VLAN_FLOW_4);
    private static final FlowRule NEXT_VLAN_FLOW_5 = buildNextVlanRule(NEXT_ECMP, DEFAULT_VLAN);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_5 = new DefaultFlowEntry(NEXT_VLAN_FLOW_5);
    private static final FlowRule NEXT_VLAN_FLOW_6 = buildNextVlanRule(NEXT_BROADCAST_2, HOST_VLAN_2);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_6 = new DefaultFlowEntry(NEXT_VLAN_FLOW_6);

    private static final FlowRule NEXT_HASHED_FLOW_1 = buildNextHashedRule(NEXT_BRIDGING, GROUP_ID_BRIDGING);
    private static final FlowEntry NEXT_HASHED_FLOW_ENTRY_1 = new DefaultFlowEntry(NEXT_HASHED_FLOW_1);
    private static final FlowRule NEXT_HASHED_FLOW_2 = buildNextHashedRule(NEXT_ROUTING, GROUP_ID_ROUTING);
    private static final FlowEntry NEXT_HASHED_FLOW_ENTRY_2 = new DefaultFlowEntry(NEXT_HASHED_FLOW_2);
    private static final FlowRule NEXT_HASHED_FLOW_3 = buildNextHashedRule(NEXT_MPLS, GROUP_ID_MPLS);
    private static final FlowEntry NEXT_HASHED_FLOW_ENTRY_3 = new DefaultFlowEntry(NEXT_HASHED_FLOW_3);
    private static final FlowRule NEXT_HASHED_FLOW_4 = buildNextHashedRule(NEXT_ECMP, GROUP_ID_ECMP);
    private static final FlowEntry NEXT_HASHED_FLOW_ENTRY_4 = new DefaultFlowEntry(NEXT_HASHED_FLOW_4);

    private static final FlowRule NEXT_MCAST_FLOW = buildNextMcastRule(NEXT_BROADCAST, GROUP_ID_BROADCAST);
    private static final FlowEntry NEXT_MCAST_FLOW_ENTRY = new DefaultFlowEntry(NEXT_MCAST_FLOW);
    private static final FlowRule NEXT_MCAST_FLOW_2 = buildNextMcastRule(NEXT_BROADCAST_2, GROUP_ID_BROADCAST_2);
    private static final FlowEntry NEXT_MCAST_FLOW_ENTRY_2 = new DefaultFlowEntry(NEXT_MCAST_FLOW_2);

    private static final Group BROADCAST_GROUP = buildMcastGroup(BRODCAST_PORTS, NEXT_BROADCAST, GROUP_ID_BROADCAST);
    private static final Group BROADCAST_GROUP_2 = buildMcastGroup(BRODCAST_PORTS_2, NEXT_BROADCAST_2,
            GROUP_ID_BROADCAST_2);

    private static final GroupBucket BRIDGING_BUCKET = buildHashedBucket(MEMBER_1, null, null, null);
    private static final GroupBuckets BRIDGING_BUCKETS = new GroupBuckets(ImmutableList.of(BRIDGING_BUCKET));
    private static final Group BRIDGING_GROUP = buildHashedGroup(BRIDGING_BUCKETS, NEXT_BRIDGING, GROUP_ID_BRIDGING);

    private static final GroupBucket ROUTING_BUCKET = buildHashedBucket(DOWN_PORT, LEAF_MAC, HOST_MAC, null);
    private static final GroupBuckets ROUTING_BUCKETS = new GroupBuckets(ImmutableList.of(ROUTING_BUCKET));
    private static final Group ROUTING_GROUP = buildHashedGroup(ROUTING_BUCKETS, NEXT_ROUTING, GROUP_ID_ROUTING);

    private static final GroupBucket MPLS_BUCKET = buildHashedBucket(UP_PORT_2, LEAF_MAC, SPINE_MAC_1, null);
    private static final GroupBuckets MPLS_BUCKETS = new GroupBuckets(ImmutableList.of(MPLS_BUCKET));
    private static final Group MPLS_GROUP = buildHashedGroup(MPLS_BUCKETS, NEXT_MPLS, GROUP_ID_MPLS);

    private static final GroupBucket ECMP_BUCKET_1 = buildHashedBucket(UP_PORT_1, LEAF_MAC, SPINE_MAC_1,
            MPLS_LABEL);
    private static final GroupBucket ECMP_BUCKET_2 = buildHashedBucket(UP_PORT_2, LEAF_MAC, SPINE_MAC_2,
            MPLS_LABEL);
    private static final GroupBuckets ECMP_BUCKETS = new GroupBuckets(ImmutableList.of(ECMP_BUCKET_1, ECMP_BUCKET_2));
    private static final Group ECMP_GROUP = buildHashedGroup(ECMP_BUCKETS, NEXT_ECMP, GROUP_ID_ECMP);

    private static final FlowRule EGRESS_VLAN_FLOW_1 = buildEgressVlanRule(DOWN_PORT, HOST_VLAN_1, false);
    private static final FlowEntry EGRESS_VLAN_FLOW_ENTRY_1 = new DefaultFlowEntry(EGRESS_VLAN_FLOW_1);
    private static final FlowRule EGRESS_VLAN_FLOW_2 = buildEgressVlanRule(UP_PORT_1, DEFAULT_VLAN, false);
    private static final FlowEntry EGRESS_VLAN_FLOW_ENTRY_2 = new DefaultFlowEntry(EGRESS_VLAN_FLOW_2);
    private static final FlowRule EGRESS_VLAN_FLOW_3 = buildEgressVlanRule(UP_PORT_2, DEFAULT_VLAN, false);
    private static final FlowEntry EGRESS_VLAN_FLOW_ENTRY_3 = new DefaultFlowEntry(EGRESS_VLAN_FLOW_3);
    private static final FlowRule EGRESS_VLAN_FLOW_4 = buildEgressVlanRule(MEMBER_1, HOST_VLAN_1, false);
    private static final FlowEntry EGRESS_VLAN_FLOW_ENTRY_4 = new DefaultFlowEntry(EGRESS_VLAN_FLOW_4);
    private static final FlowRule EGRESS_VLAN_FLOW_5 = buildEgressVlanRule(MEMBER_2, HOST_VLAN_1, false);
    private static final FlowEntry EGRESS_VLAN_FLOW_ENTRY_5 = new DefaultFlowEntry(EGRESS_VLAN_FLOW_5);

    // Represents the device state
    public static List<DataPlaneEntity> getDataPlaneEntities(TraceableTest test) {
        List<FlowEntry> flowRules = ImmutableList.of(
                DOWN_PORT_VLAN_FLOW_ENTRY, UP_PORT_VLAN_FLOW_ENTRY, DOWN_PORT_VLAN_TAG_FLOW_ENTRY,
                FWD_CLASS_IPV4_FLOW_ENTRY_1, FWD_CLASS_IPV4_FLOW_ENTRY_2, FWD_CLASS_IPV4_FLOW_ENTRY_3,
                FWD_CLASS_IPV4_FLOW_ENTRY_4, FWD_CLASS_IPV4_FLOW_ENTRY_5, L2_BRIDGING_FLOW_ENTRY,
                L2_BROADCAST_FLOW_ENTRY, L2_BROADCAST_FLOW_ENTRY_2, DEFAULT_IPV4_ROUTING_FLOW_ENTRY,
                IPV4_ROUTING_FLOW_ENTRY, SUBNET_IPV4_ROUTING_FLOW_ENTRY, MPLS_FLOW_ENTRY,
                PUNT_IP_ACL_FLOW_ENTRY, PUNT_IP_ACL_FLOW_ENTRY_1, ARP_ACL_FLOW_ENTRY,
                PUNT_LLDP_ACL_FLOW_ENTRY, PUNT_BDDP_ACL_FLOW_ENTRY, NEXT_VLAN_FLOW_ENTRY_1,
                NEXT_VLAN_FLOW_ENTRY_2, NEXT_VLAN_FLOW_ENTRY_3, NEXT_VLAN_FLOW_ENTRY_4,
                NEXT_VLAN_FLOW_ENTRY_5, NEXT_VLAN_FLOW_ENTRY_6, NEXT_HASHED_FLOW_ENTRY_1,
                NEXT_HASHED_FLOW_ENTRY_2, NEXT_HASHED_FLOW_ENTRY_3, NEXT_HASHED_FLOW_ENTRY_4,
                NEXT_MCAST_FLOW_ENTRY, NEXT_MCAST_FLOW_ENTRY_2, EGRESS_VLAN_FLOW_ENTRY_1,
                EGRESS_VLAN_FLOW_ENTRY_2, EGRESS_VLAN_FLOW_ENTRY_3, EGRESS_VLAN_FLOW_ENTRY_4,
                EGRESS_VLAN_FLOW_ENTRY_5);
        List<Group> groups = ImmutableList.of(
                BROADCAST_GROUP, BROADCAST_GROUP_2, BRIDGING_GROUP,
                ROUTING_GROUP, MPLS_GROUP, ECMP_GROUP);

        // Builds the state representation
        List<DataPlaneEntity> dataPlaneEntities = Lists.newArrayList();
        flowRules.forEach(flowRule -> dataPlaneEntities.add(new DataPlaneEntity(flowRule)));
        groups.forEach(group -> dataPlaneEntities.add(new DataPlaneEntity(group)));
        return dataPlaneEntities;
    }

    // Returns the expected hit chains (order matters!)
    public static List<List<DataPlaneEntity>> getHitChains(TraceableTest test) {
        List<List<FlowEntry>> flowRules = Lists.newArrayList();
        List<List<Group>> groups = Lists.newArrayList();
        // Builds the hit chains
        List<List<DataPlaneEntity>> chains = Lists.newArrayList();

        // Flows and groups by test
        if (test.equals(PUNT_IP_UNTAG)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(FWD_CLASS_IPV4_FLOW_ENTRY_1),
                new DataPlaneEntity(DEFAULT_IPV4_ROUTING_FLOW_ENTRY), new DataPlaneEntity(PUNT_IP_ACL_FLOW_ENTRY))
            );
        } else if (test.equals(PUNT_IP_TAG)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_TAG_FLOW_ENTRY), new DataPlaneEntity(FWD_CLASS_IPV4_FLOW_ENTRY_5),
                new DataPlaneEntity(DEFAULT_IPV4_ROUTING_FLOW_ENTRY), new DataPlaneEntity(PUNT_IP_ACL_FLOW_ENTRY_1))
            );
        } else if (test.equals(ARP_UNTAG)) {
            // Controller chain
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY),
                new DataPlaneEntity(ARP_ACL_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_4),
                new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY)));
            // DOWN member chain
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY),
                new DataPlaneEntity(ARP_ACL_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_4),
                new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY), new DataPlaneEntity(BROADCAST_GROUP)));
            // Member 2 chain
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY),
                new DataPlaneEntity(ARP_ACL_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_4),
                new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY), new DataPlaneEntity(BROADCAST_GROUP),
                new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_5)));
            // Member 1 chain
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY),
                new DataPlaneEntity(ARP_ACL_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_4),
                new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY), new DataPlaneEntity(BROADCAST_GROUP),
                new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_4)));
        } else if (test.equals(PUNT_LLDP)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(UP_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(PUNT_LLDP_ACL_FLOW_ENTRY)));
        } else if (test.equals(L2_BRIDG_UNTAG)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BRIDGING_FLOW_ENTRY),
                new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_1), new DataPlaneEntity(NEXT_HASHED_FLOW_ENTRY_1),
                new DataPlaneEntity(BRIDGING_GROUP), new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_4)));
        } else if (test.equals(L2_BRIDG_MISS)) {
            chains.add(ImmutableList.of(
                    new DataPlaneEntity(DOWN_PORT_VLAN_TAG_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY_2),
                    new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_6), new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY_2),
                    new DataPlaneEntity(BROADCAST_GROUP_2)));
        } else if (test.equals(L2_BROAD_UNTAG)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY),
                new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_4), new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY),
                new DataPlaneEntity(BROADCAST_GROUP)));
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY),
                new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_4), new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY),
                new DataPlaneEntity(BROADCAST_GROUP), new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_5)));
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(L2_BROADCAST_FLOW_ENTRY),
                new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_4), new DataPlaneEntity(NEXT_MCAST_FLOW_ENTRY),
                new DataPlaneEntity(BROADCAST_GROUP), new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_4)));
        } else if (test.equals(L3_UCAST_UNTAG)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(UP_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(FWD_CLASS_IPV4_FLOW_ENTRY_2),
                new DataPlaneEntity(IPV4_ROUTING_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_2),
                new DataPlaneEntity(NEXT_HASHED_FLOW_ENTRY_2), new DataPlaneEntity(ROUTING_GROUP),
                new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_1)));
        } else if (test.equals(MPLS_ECMP)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(UP_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(FWD_CLASS_IPV4_FLOW_ENTRY_3),
                new DataPlaneEntity(MPLS_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_3),
                new DataPlaneEntity(NEXT_HASHED_FLOW_ENTRY_3), new DataPlaneEntity(MPLS_GROUP),
                new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_3)));
        } else if (test.equals(L3_ECMP)) {
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(FWD_CLASS_IPV4_FLOW_ENTRY_1),
                new DataPlaneEntity(SUBNET_IPV4_ROUTING_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_5),
                new DataPlaneEntity(NEXT_HASHED_FLOW_ENTRY_4), new DataPlaneEntity(ECMP_GROUP),
                new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_2)));
            chains.add(ImmutableList.of(
                new DataPlaneEntity(DOWN_PORT_VLAN_FLOW_ENTRY), new DataPlaneEntity(FWD_CLASS_IPV4_FLOW_ENTRY_1),
                new DataPlaneEntity(SUBNET_IPV4_ROUTING_FLOW_ENTRY), new DataPlaneEntity(NEXT_VLAN_FLOW_ENTRY_5),
                new DataPlaneEntity(NEXT_HASHED_FLOW_ENTRY_4), new DataPlaneEntity(ECMP_GROUP),
                new DataPlaneEntity(EGRESS_VLAN_FLOW_ENTRY_3)));
        }

        return chains;
    }

    // Helper methods for the port vlan flow rules
    private static FlowRule buildVlanPortRule(PortNumber inPort, VlanId vlanId,
                                              VlanId innerVlanId, VlanId internalVlan) {

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchInPort(inPort);
        PiAction piAction;
        selector.matchPi(buildPiCriterionVlan(vlanId, innerVlanId));
        if (!vlanValid(vlanId)) {
            piAction = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)
                    .withParameter(new PiActionParam(P4InfoConstants.VLAN_ID, internalVlan.toShort()))
                    .build();
        } else {
            selector.matchVlanId(vlanId);
            if (vlanValid(innerVlanId)) {
                selector.matchInnerVlanId(innerVlanId);
            }
            piAction = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT)
                    .build();
        }

        return DefaultFlowRule.builder()
                .withPriority(PRIORITY)
                .withSelector(selector.build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piAction).build())
                .fromApp(APP_ID)
                .forDevice(DEVICE_ID)
                .makePermanent()
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN)
                .build();
    }

    private static boolean vlanValid(VlanId vlanId) {
        return (vlanId != null && !vlanId.equals(VlanId.NONE));
    }

    private static PiCriterion buildPiCriterionVlan(VlanId vlanId, VlanId innerVlanId) {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_VLAN_IS_VALID, vlanValid(vlanId) ? ONE : ZERO);
        return piCriterionBuilder.build();
    }

    private static FlowRule buildIPFwdClassifierRule(PortNumber inPort, MacAddress dstMac, MacAddress dstMacMask,
                                                     short ethType) {
        PiActionParam classParam = new PiActionParam(P4InfoConstants.FWD_TYPE,
                ImmutableByteSequence.copyFrom(FWD_IPV4_UNICAST));
        PiAction fwdClassifierAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                .withParameter(classParam)
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(fwdClassifierAction)
                .build();

        TrafficSelector.Builder sbuilder = DefaultTrafficSelector.builder()
                .matchInPort(inPort);
        if (dstMacMask != null) {
            sbuilder.matchEthDstMasked(dstMac, dstMacMask);
        } else {
            sbuilder.matchEthDstMasked(dstMac, MacAddress.EXACT_MASK);
        }
        sbuilder.matchPi(PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, ethType)
                .build());
        TrafficSelector selector = sbuilder.build();

        return DefaultFlowRule.builder()
                .withPriority(PRIORITY)
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(APP_ID)
                .forDevice(DEVICE_ID)
                .makePermanent()
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)
                .build();
    }

    private static FlowRule buildMplsFwdClassifierRule(PortNumber inPort, MacAddress dstMac, short ethType) {
        PiActionParam classParam = new PiActionParam(P4InfoConstants.FWD_TYPE,
                ImmutableByteSequence.copyFrom(FWD_MPLS));
        PiAction fwdClassifierAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                .withParameter(classParam)
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(fwdClassifierAction)
                .build();

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(inPort)
                .matchEthDstMasked(dstMac, MacAddress.EXACT_MASK)
                .add(PiCriterion.builder()
                        .matchTernary(P4InfoConstants.HDR_ETH_TYPE, Ethernet.MPLS_UNICAST, EXACT_MATCH_ETH_TYPE)
                        .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, ethType)
                        .build())
                .build();

        return DefaultFlowRule.builder()
                .withPriority(PRIORITY + 1)
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(APP_ID)
                .forDevice(DEVICE_ID)
                .makePermanent()
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)
                .build();
    }

    private static FlowRule buildBridgingRule(VlanId vlanId, MacAddress ethDst, Integer nextId,
                                              boolean isBroadcast) {
        int priority = 5;
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchVlanId(vlanId);
        if (!isBroadcast) {
            priority = PRIORITY;
            selector.matchEthDst(ethDst);
        }
        PiActionParam nextIdParam = new PiActionParam(P4InfoConstants.NEXT_ID, nextId);
        PiAction setNextIdAction = PiAction.builder()
                .withParameter(nextIdParam)
                .withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_BRIDGING)
                .build();
        TrafficTreatment setNextIdTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(setNextIdAction)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING)
                .withPriority(priority)
                .makePermanent()
                .withSelector(selector.build())
                .withTreatment(setNextIdTreatment)
                .fromApp(APP_ID)
                .build();
    }

    private static FlowRule buildIPv4RoutingRule(IpPrefix ipDst, Integer nextId) {
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        if (ipDst.prefixLength() != 0) {
            selectorBuilder.matchIPDst(ipDst);
        }
        PiActionParam nextIdParam = new PiActionParam(P4InfoConstants.NEXT_ID, nextId);
        PiAction setNextIdAction = PiAction.builder()
                .withParameter(nextIdParam)
                .withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V4)
                .build();
        TrafficTreatment setNextIdTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(setNextIdAction)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(selectorBuilder.build())
                .withTreatment(setNextIdTreatment)
                .fromApp(APP_ID)
                .build();
    }

    private static FlowRule buildMplsRule(MplsLabel label, Integer nextId) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchMplsLabel(label)
                .build();
        PiActionParam nextIdParam = new PiActionParam(P4InfoConstants.NEXT_ID, nextId);
        PiAction setNextIdAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_POP_MPLS_AND_NEXT)
                .withParameter(nextIdParam)
                .build();
        TrafficTreatment setNextIdTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(setNextIdAction)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(selector)
                .withTreatment(setNextIdTreatment)
                .fromApp(APP_ID)
                .build();
    }

    private static FlowRule buildPuntIpAclRule(short ethType, IpPrefix puntIp) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(ethType)
                .matchIPDst(puntIp)
                .build();
        final TrafficTreatment piTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_INGRESS_ACL_PUNT_TO_CPU)
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(piTreatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .makePermanent()
                .withPriority(ACL_PRIORITY_1)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    private static FlowRule buildArpAclRule() {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(ARP.ethType().toShort())
                .build();
        final TrafficTreatment piTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_INGRESS_ACL_COPY_TO_CPU)
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(piTreatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .makePermanent()
                .withPriority(ACL_PRIORITY_2)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    private static FlowRule buildPuntEthTypeAclRule(short ethType) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(ethType)
                .build();
        final TrafficTreatment piTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_INGRESS_ACL_PUNT_TO_CPU)
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(piTreatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .makePermanent()
                .withPriority(ACL_PRIORITY_1)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    private static FlowRule buildNextVlanRule(Integer nextId, VlanId vlanId) {
        TrafficSelector selector = buildNextSelector(nextId);
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_VLAN)
                .withParameter(new PiActionParam(P4InfoConstants.VLAN_ID, vlanId.toShort()))
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(piAction)
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_NEXT_VLAN)
                .makePermanent()
                .withPriority(0)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    private static FlowRule buildNextHashedRule(Integer nextId, GroupId groupId) {
        TrafficSelector nextIdSelector = buildNextSelector(nextId);
        PiActionProfileGroupId actionGroupId = PiActionProfileGroupId.of(groupId.id());
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(actionGroupId)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .makePermanent()
                .withPriority(0)
                .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED)
                .withSelector(nextIdSelector)
                .withTreatment(treatment)
                .build();
    }

    private static FlowRule buildNextMcastRule(Integer nextId, GroupId groupId) {
        TrafficSelector nextIdSelector = buildNextSelector(nextId);
        PiAction setMcGroupAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_MCAST_GROUP_ID)
                .withParameter(new PiActionParam(
                        P4InfoConstants.GROUP_ID, groupId.id()))
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(setMcGroupAction)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .makePermanent()
                .withPriority(0)
                .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_MULTICAST)
                .withSelector(nextIdSelector)
                .withTreatment(treatment)
                .build();
    }

    private static TrafficSelector buildNextSelector(Integer nextId) {
        PiCriterion nextIdCriterion = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_NEXT_ID, nextId)
                .build();
        return DefaultTrafficSelector.builder()
                .matchPi(nextIdCriterion)
                .build();
    }

    private static Group buildMcastGroup(Set<PortNumber> ports, Integer nextId, GroupId groupId) {
        TrafficTreatment groupTreatment;
        List<GroupBucket> allBuckets = Lists.newArrayList();
        for (PortNumber port : ports) {
            groupTreatment = DefaultTrafficTreatment.builder()
                    .setOutput(port)
                    .build();
            allBuckets.add(DefaultGroupBucket.createAllGroupBucket(groupTreatment));
        }
        GroupBuckets allGroupBuckets = new GroupBuckets(allBuckets);
        GroupKey allGroupKey = new DefaultGroupKey(FabricUtils.KRYO.serialize(nextId));
        GroupDescription groupDescription = new DefaultGroupDescription(DEVICE_ID, GroupDescription.Type.ALL,
                allGroupBuckets, allGroupKey, nextId, APP_ID);
        return new DefaultGroup(groupId, groupDescription);
    }

    private static GroupBucket buildHashedBucket(PortNumber outputPort, MacAddress ethSrc, MacAddress ethDst,
                                                 MplsLabel mplsLabel) {
        final PiAction.Builder actionBuilder = PiAction.builder()
                .withParameter(new PiActionParam(P4InfoConstants.PORT_NUM, outputPort.toLong()));
        PiAction action;
        TrafficTreatment treatment;
        if (ethDst != null && ethSrc != null) {
            actionBuilder.withParameter(new PiActionParam(
                    P4InfoConstants.SMAC, ethSrc.toBytes()));
            actionBuilder.withParameter(new PiActionParam(
                    P4InfoConstants.DMAC, ethDst.toBytes()));
            if (mplsLabel != null) {
                action = actionBuilder
                        .withParameter(new PiActionParam(P4InfoConstants.LABEL, mplsLabel.toInt()))
                        .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_MPLS_ROUTING_HASHED)
                        .build();
            } else {
                action =  actionBuilder
                        .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_ROUTING_HASHED)
                        .build();
            }
        } else {
            action = actionBuilder
                    .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_OUTPUT_HASHED)
                    .build();
        }
        treatment = DefaultTrafficTreatment.builder()
                .piTableAction(action)
                .build();
        return DefaultGroupBucket.createSelectGroupBucket(treatment);
    }

    private static final Group buildHashedGroup(GroupBuckets groupBuckets, int nextId, GroupId groupId) {
        final PiGroupKey groupKey = new PiGroupKey(
                P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED,
                P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED_PROFILE,
                groupId.id());
        GroupDescription groupDescription = new DefaultGroupDescription(DEVICE_ID, GroupDescription.Type.SELECT,
                groupBuckets, groupKey, nextId, APP_ID);
        return new DefaultGroup(groupId, groupDescription);
    }

    private static FlowRule buildEgressVlanRule(PortNumber outPort, VlanId vlanId, boolean push) {
        PiCriterion egressVlanTableMatch = PiCriterion.builder()
            .matchExact(P4InfoConstants.HDR_EG_PORT, outPort.toLong())
            .build();
        TrafficSelector selectorForEgressVlan = DefaultTrafficSelector.builder()
            .matchPi(egressVlanTableMatch)
            .matchVlanId(vlanId)
            .build();
        PiAction.Builder piActionForEgressVlan = PiAction.builder();
        if (push) {
            piActionForEgressVlan.withId(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_PUSH_VLAN);
        } else {
            piActionForEgressVlan.withId(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_POP_VLAN);
        }
        TrafficTreatment treatmentForEgressVlan = DefaultTrafficTreatment.builder()
            .piTableAction(piActionForEgressVlan.build())
            .build();
        return DefaultFlowRule.builder()
            .withSelector(selectorForEgressVlan)
            .withTreatment(treatmentForEgressVlan)
            .forTable(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN)
            .makePermanent()
            .withPriority(0)
            .forDevice(DEVICE_ID)
            .fromApp(APP_ID)
            .build();
    }

}
