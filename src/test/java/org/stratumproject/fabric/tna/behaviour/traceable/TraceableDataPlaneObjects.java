// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

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
import org.onosproject.net.group.Group;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;
import org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest;

import java.util.List;

import static org.onlab.packet.EthType.EtherType.ARP;
import static org.onlab.packet.EthType.EtherType.BDDP;
import static org.onlab.packet.EthType.EtherType.IPV4;
import static org.onlab.packet.EthType.EtherType.IPV6;
import static org.onlab.packet.EthType.EtherType.LLDP;
import static org.stratumproject.fabric.tna.behaviour.traceable.FabricTraceableMetadata.FWD_IPV4_UNICAST;
import static org.stratumproject.fabric.tna.behaviour.traceable.FabricTraceableMetadata.FWD_MPLS;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.ACL_PRIORITY_1;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.ACL_PRIORITY_2;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.APP_ID;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.DEFAULT_IPV4;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.DEFAULT_VLAN;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.DEVICE_ID;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.DOWN_PORT;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.EXACT_MATCH_ETH_TYPE;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.GROUP_ID_BRIDGING;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.GROUP_ID_BROADCAST;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.GROUP_ID_ECMP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.GROUP_ID_MPLS;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.GROUP_ID_ROUTING;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.HOST_IPV4;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.HOST_MAC;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.HOST_VLAN;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.LEAF_MAC;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.MPLS_LABEL;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.NEXT_BRIDGING;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.NEXT_BROADCAST;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.NEXT_ECMP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.NEXT_MPLS;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.NEXT_ROUTING;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.ONE;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.PRIORITY;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.PUNT_IPV4;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.SUBNET_IPV4;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.ARP_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L2_BRIDG_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L2_BROAD_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L3_ECMP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L3_UCAST_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.MPLS_ECMP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.PUNT_IP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.PUNT_LLDP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.UP_PORT;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.ZERO;

/**
 * Helper class for dataplane objects related to the Traceable tests.
 */
final class TraceableDataPlaneObjects {

    private TraceableDataPlaneObjects() {
        // Banning construction
    }

    private static final FlowRule DOWN_PORT_VLAN_FLOW = buildVlanPortRule(
            DOWN_PORT, VlanId.NONE, VlanId.NONE, HOST_VLAN);
    private static final FlowEntry DOWN_PORT_VLAN_FLOW_ENTRY = new DefaultFlowEntry(DOWN_PORT_VLAN_FLOW);
    private static final FlowRule UP_PORT_VLAN_FLOW = buildVlanPortRule(
            UP_PORT, VlanId.NONE, VlanId.NONE, DEFAULT_VLAN);
    private static final FlowEntry UP_PORT_VLAN_FLOW_ENTRY = new DefaultFlowEntry(UP_PORT_VLAN_FLOW);

    private static final FlowRule FWD_CLASS_IPV4_FLOW_1 = buildIPFwdClassifierRule(
            DOWN_PORT, LEAF_MAC, null, IPV4.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_1 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_1);
    private static final FlowRule FWD_CLASS_IPV4_FLOW_2 = buildIPFwdClassifierRule(
            UP_PORT, LEAF_MAC, null, IPV4.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_2 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_2);
    private static final FlowRule FWD_CLASS_IPV4_FLOW_3 = buildMplsFwdClassifierRule(
            UP_PORT, LEAF_MAC, IPV4.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_3 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_3);
    private static final FlowRule FWD_CLASS_IPV4_FLOW_4 = buildMplsFwdClassifierRule(
            UP_PORT, LEAF_MAC, IPV6.ethType().toShort());
    private static final FlowEntry FWD_CLASS_IPV4_FLOW_ENTRY_4 = new DefaultFlowEntry(FWD_CLASS_IPV4_FLOW_4);

    private static final FlowRule L2_BRIDGING_FLOW = buildBridgingRule(HOST_VLAN, HOST_MAC, NEXT_BRIDGING, false);
    private static final FlowEntry L2_BRIDGING_FLOW_ENTRY = new DefaultFlowEntry(L2_BRIDGING_FLOW);
    private static final FlowRule L2_BROADCAST_FLOW = buildBridgingRule(HOST_VLAN, null, NEXT_BROADCAST, true);
    private static final FlowEntry L2_BROADCAST_FLOW_ENTRY = new DefaultFlowEntry(L2_BROADCAST_FLOW);

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

    private static final FlowRule NEXT_VLAN_FLOW_1 = buildNextVlanRule(NEXT_BRIDGING, HOST_VLAN);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_1 = new DefaultFlowEntry(NEXT_VLAN_FLOW_1);
    private static final FlowRule NEXT_VLAN_FLOW_2 = buildNextVlanRule(NEXT_ROUTING, DEFAULT_VLAN);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_2 = new DefaultFlowEntry(NEXT_VLAN_FLOW_2);
    private static final FlowRule NEXT_VLAN_FLOW_3 = buildNextVlanRule(NEXT_MPLS, DEFAULT_VLAN);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_3 = new DefaultFlowEntry(NEXT_VLAN_FLOW_3);
    private static final FlowRule NEXT_VLAN_FLOW_4 = buildNextVlanRule(NEXT_BROADCAST, HOST_VLAN);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_4 = new DefaultFlowEntry(NEXT_VLAN_FLOW_4);
    private static final FlowRule NEXT_VLAN_FLOW_5 = buildNextVlanRule(NEXT_ECMP, HOST_VLAN);
    private static final FlowEntry NEXT_VLAN_FLOW_ENTRY_5 = new DefaultFlowEntry(NEXT_VLAN_FLOW_5);

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

    // Represents the device state
    public static List<DataPlaneEntity> getDataPlaneEntities(TraceableTest test) {
        List<FlowEntry> flowRules = ImmutableList.of(
                DOWN_PORT_VLAN_FLOW_ENTRY, UP_PORT_VLAN_FLOW_ENTRY, FWD_CLASS_IPV4_FLOW_ENTRY_1,
                FWD_CLASS_IPV4_FLOW_ENTRY_2, FWD_CLASS_IPV4_FLOW_ENTRY_3, FWD_CLASS_IPV4_FLOW_ENTRY_4,
                L2_BRIDGING_FLOW_ENTRY, L2_BROADCAST_FLOW_ENTRY, DEFAULT_IPV4_ROUTING_FLOW_ENTRY,
                IPV4_ROUTING_FLOW_ENTRY, SUBNET_IPV4_ROUTING_FLOW_ENTRY, MPLS_FLOW_ENTRY,
                PUNT_IP_ACL_FLOW_ENTRY, ARP_ACL_FLOW_ENTRY, PUNT_LLDP_ACL_FLOW_ENTRY,
                PUNT_BDDP_ACL_FLOW_ENTRY, NEXT_VLAN_FLOW_ENTRY_1, NEXT_VLAN_FLOW_ENTRY_2,
                NEXT_VLAN_FLOW_ENTRY_3, NEXT_VLAN_FLOW_ENTRY_4, NEXT_VLAN_FLOW_ENTRY_5,
                NEXT_HASHED_FLOW_ENTRY_1, NEXT_HASHED_FLOW_ENTRY_2, NEXT_HASHED_FLOW_ENTRY_3,
                NEXT_HASHED_FLOW_ENTRY_4, NEXT_MCAST_FLOW_ENTRY);
        List<Group> groups = ImmutableList.of();

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

        // Flows and groups by test
        if (test.equals(PUNT_IP)) {
            flowRules.add(ImmutableList.of(
                    DOWN_PORT_VLAN_FLOW_ENTRY, FWD_CLASS_IPV4_FLOW_ENTRY_1, DEFAULT_IPV4_ROUTING_FLOW_ENTRY,
                    PUNT_IP_ACL_FLOW_ENTRY));
        } else if (test.equals(ARP_UNTAG)) {
            flowRules.add(ImmutableList.of(
                    DOWN_PORT_VLAN_FLOW_ENTRY, L2_BROADCAST_FLOW_ENTRY, ARP_ACL_FLOW_ENTRY,
                    NEXT_VLAN_FLOW_ENTRY_4, NEXT_MCAST_FLOW_ENTRY));
        } else if (test.equals(PUNT_LLDP)) {
            flowRules.add(ImmutableList.of(
                    UP_PORT_VLAN_FLOW_ENTRY, PUNT_LLDP_ACL_FLOW_ENTRY));
        } else if (test.equals(L2_BRIDG_UNTAG)) {
            flowRules.add(ImmutableList.of(
                    DOWN_PORT_VLAN_FLOW_ENTRY, L2_BRIDGING_FLOW_ENTRY, NEXT_VLAN_FLOW_ENTRY_1,
                    NEXT_HASHED_FLOW_ENTRY_1));
        } else if (test.equals(L2_BROAD_UNTAG)) {
            flowRules.add(ImmutableList.of(
                    DOWN_PORT_VLAN_FLOW_ENTRY, L2_BROADCAST_FLOW_ENTRY, NEXT_VLAN_FLOW_ENTRY_4,
                    NEXT_MCAST_FLOW_ENTRY));
        } else if (test.equals(L3_UCAST_UNTAG)) {
            flowRules.add(ImmutableList.of(
                    UP_PORT_VLAN_FLOW_ENTRY, FWD_CLASS_IPV4_FLOW_ENTRY_2, IPV4_ROUTING_FLOW_ENTRY,
                    NEXT_VLAN_FLOW_ENTRY_2, NEXT_HASHED_FLOW_ENTRY_2));
        } else if (test.equals(MPLS_ECMP)) {
            flowRules.add(ImmutableList.of(
                    UP_PORT_VLAN_FLOW_ENTRY, FWD_CLASS_IPV4_FLOW_ENTRY_3, MPLS_FLOW_ENTRY,
                    NEXT_VLAN_FLOW_ENTRY_3, NEXT_HASHED_FLOW_ENTRY_3));
        } else if (test.equals(L3_ECMP)) {
            flowRules.add(ImmutableList.of(
                    DOWN_PORT_VLAN_FLOW_ENTRY, FWD_CLASS_IPV4_FLOW_ENTRY_1, SUBNET_IPV4_ROUTING_FLOW_ENTRY,
                    NEXT_VLAN_FLOW_ENTRY_5, NEXT_HASHED_FLOW_ENTRY_4));
        }

        // Builds the hit chains
        List<List<DataPlaneEntity>> chains = Lists.newArrayList();
        List<DataPlaneEntity> dataPlaneEntities = Lists.newArrayList();
        int end = Math.max(flowRules.size(), groups.size());
        int i = 0;
        while (i < end) {
            if (i < flowRules.size()) {
                flowRules.get(i).forEach(flowRule -> dataPlaneEntities.add(new DataPlaneEntity(flowRule)));
            }
            if (i < groups.size()) {
                groups.get(i).forEach(group -> dataPlaneEntities.add(new DataPlaneEntity(group)));
            }
            chains.add(ImmutableList.copyOf(dataPlaneEntities));
            dataPlaneEntities.clear();
            i = i + 1;
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
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchIPDst(ipDst)
                .build();
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
                .withSelector(selector)
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

}
