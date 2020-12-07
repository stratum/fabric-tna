// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0
package org.stratumproject.fabric.tna.behaviour.pipeliner;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flowobjective.DefaultNextObjective;
import org.onosproject.net.flowobjective.NextObjective;
import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
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

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

/**
 * Test cases for fabric.p4 pipeline next control block.
 */
public class FabricNextPipelinerTest extends FabricPipelinerTest {

    private NextObjectiveTranslator translatorHashed;
    // TODO: add profile with simple next or remove references
    // private NextObjectiveTranslator translatorSimple;

    private FlowRule vlanMetaFlowRule;

    @Before
    public void setup() {
        super.doSetup();

        translatorHashed = new NextObjectiveTranslator(DEVICE_ID, capabilitiesHashed);
        // TODO: add profile with simple next or remove test
        // translatorSimple = new NextObjectiveTranslator(DEVICE_ID, capabilitiesSimple);

        PiCriterion nextIdCriterion = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_NEXT_ID, NEXT_ID_1)
                .build();
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(nextIdCriterion)
                .build();
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_VLAN)
                .withParameter(new PiActionParam(P4InfoConstants.VLAN_ID, VLAN_100.toShort()))
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(piAction)
                .build();
        vlanMetaFlowRule = DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_NEXT_VLAN)
                .makePermanent()
                // FIXME: currently next objective doesn't support priority, ignore this
                .withPriority(0)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    /**
     * Test program ecmp output group for Hashed table.
     */
    @Test
    public void testHashedOutput() throws Exception {
        PiAction piAction1 = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_ROUTING_HASHED)
                .withParameter(new PiActionParam(
                        P4InfoConstants.SMAC, ROUTER_MAC.toBytes()))
                .withParameter(new PiActionParam(
                        P4InfoConstants.DMAC, HOST_MAC.toBytes()))
                .withParameter(new PiActionParam(
                        P4InfoConstants.PORT_NUM, PORT_1.toLong()))
                .build();
        PiAction piAction2 = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_ROUTING_HASHED)
                .withParameter(new PiActionParam(
                        P4InfoConstants.SMAC, ROUTER_MAC.toBytes()))
                .withParameter(new PiActionParam(
                        P4InfoConstants.DMAC, HOST_MAC.toBytes()))
                .withParameter(new PiActionParam(
                        P4InfoConstants.PORT_NUM, PORT_1.toLong()))
                .build();
        TrafficTreatment treatment1 = DefaultTrafficTreatment.builder()
                .piTableAction(piAction1)
                .build();
        TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
                .piTableAction(piAction2)
                .build();

        NextObjective nextObjective = DefaultNextObjective.builder()
                .withId(NEXT_ID_1)
                .withPriority(PRIORITY)
                .withMeta(VLAN_META)
                .addTreatment(treatment1)
                .addTreatment(treatment2)
                .withType(NextObjective.Type.HASHED)
                .makePermanent()
                .fromApp(APP_ID)
                .add();

        ObjectiveTranslation actualTranslation = translatorHashed.doTranslate(nextObjective);

        // Expected hashed table flow rule.
        PiCriterion nextIdCriterion = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_NEXT_ID, NEXT_ID_1)
                .build();
        TrafficSelector nextIdSelector = DefaultTrafficSelector.builder()
                .matchPi(nextIdCriterion)
                .build();
        PiActionProfileGroupId actionGroupId = PiActionProfileGroupId.of(NEXT_ID_1);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(actionGroupId)
                .build();
        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .makePermanent()
                // FIXME: currently next objective doesn't support priority, ignore this
                .withPriority(0)
                .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED)
                .withSelector(nextIdSelector)
                .withTreatment(treatment)
                .build();

        // Expected group
        List<TrafficTreatment> treatments = ImmutableList.of(treatment1, treatment2);
        List<GroupBucket> buckets = treatments.stream()
                .map(DefaultGroupBucket::createSelectGroupBucket)
                .collect(Collectors.toList());
        GroupBuckets groupBuckets = new GroupBuckets(buckets);
        PiGroupKey groupKey = new PiGroupKey(P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED,
                P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED_PROFILE,
                NEXT_ID_1);
        GroupDescription expectedGroup = new DefaultGroupDescription(
                DEVICE_ID,
                GroupDescription.Type.SELECT,
                groupBuckets,
                groupKey,
                NEXT_ID_1,
                APP_ID
        );

        ObjectiveTranslation expectedTranslation = ObjectiveTranslation.builder()
                .addFlowRule(expectedFlowRule)
                .addFlowRule(vlanMetaFlowRule)
                .addGroup(expectedGroup)
                .build();

        assertEquals(expectedTranslation, actualTranslation);

    }

    /**
     * Test program output group for Broadcast table.
     */
    @Test
    public void testBroadcastOutput() throws FabricPipelinerException {
        TrafficTreatment treatment1 = DefaultTrafficTreatment.builder()
                .setOutput(PORT_1)
                .build();
        TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
                .popVlan()
                .setOutput(PORT_2)
                .build();
        NextObjective nextObjective = DefaultNextObjective.builder()
                .withId(NEXT_ID_1)
                .withPriority(PRIORITY)
                .addTreatment(treatment1)
                .addTreatment(treatment2)
                .withMeta(VLAN_META)
                .withType(NextObjective.Type.BROADCAST)
                .makePermanent()
                .fromApp(APP_ID)
                .add();

        ObjectiveTranslation actualTranslation = translatorHashed.doTranslate(nextObjective);

        // Should generate 3 flows:
        // - Multicast table flow that matches on next-id and set multicast group (1)
        // - Egress VLAN pop handling for treatment2 (0)
        // - Next VLAN flow (2)
        // And 2 groups:
        // - Multicast group

        // Expected multicast table flow rule.
        PiCriterion nextIdCriterion = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_NEXT_ID, NEXT_ID_1)
                .build();
        TrafficSelector nextIdSelector = DefaultTrafficSelector.builder()
                .matchPi(nextIdCriterion)
                .build();
        PiAction setMcGroupAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_MCAST_GROUP_ID)
                .withParameter(new PiActionParam(
                        P4InfoConstants.GROUP_ID, NEXT_ID_1))
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(setMcGroupAction)
                .build();
        FlowRule expectedHashedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .makePermanent()
                .withPriority(nextObjective.priority())
                .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_MULTICAST)
                .withSelector(nextIdSelector)
                .withTreatment(treatment)
                .build();

        // Expected egress VLAN POP flow rule.
        PiCriterion egressVlanTableMatch = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_EG_PORT, PORT_2.toLong())
                .build();
        TrafficSelector selectorForEgressVlan = DefaultTrafficSelector.builder()
                .matchPi(egressVlanTableMatch)
                .matchVlanId(VLAN_100)
                .build();
        PiAction piActionForEgressVlan = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_POP_VLAN)
                .build();
        TrafficTreatment treatmentForEgressVlan = DefaultTrafficTreatment.builder()
                .piTableAction(piActionForEgressVlan)
                .build();
        FlowRule expectedEgressVlanRule = DefaultFlowRule.builder()
                .withSelector(selectorForEgressVlan)
                .withTreatment(treatmentForEgressVlan)
                .forTable(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN)
                .makePermanent()
                .withPriority(nextObjective.priority())
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();

        // Expected ALL group.
        TrafficTreatment allGroupTreatment1 = DefaultTrafficTreatment.builder()
                .setOutput(PORT_1)
                .build();
        TrafficTreatment allGroupTreatment2 = DefaultTrafficTreatment.builder()
                .setOutput(PORT_2)
                .build();
        List<TrafficTreatment> allTreatments = ImmutableList.of(
                allGroupTreatment1, allGroupTreatment2);
        List<GroupBucket> allBuckets = allTreatments.stream()
                .map(DefaultGroupBucket::createAllGroupBucket)
                .collect(Collectors.toList());
        GroupBuckets allGroupBuckets = new GroupBuckets(allBuckets);
        GroupKey allGroupKey = new DefaultGroupKey(FabricUtils.KRYO.serialize(NEXT_ID_1));
        GroupDescription expectedAllGroup = new DefaultGroupDescription(
                DEVICE_ID,
                GroupDescription.Type.ALL,
                allGroupBuckets,
                allGroupKey,
                NEXT_ID_1,
                APP_ID
        );

        ObjectiveTranslation expectedTranslation = ObjectiveTranslation.builder()
                .addFlowRule(expectedHashedFlowRule)
                .addFlowRule(vlanMetaFlowRule)
                .addFlowRule(expectedEgressVlanRule)
                .addGroup(expectedAllGroup)
                .build();

        assertEquals(expectedTranslation, actualTranslation);
    }

    // TODO: add profile with simple next or remove tests
    // /**
    //  * Test program output rule for Simple table. Ignored: unsupported.
    //  */
    // @Test
    // public void testSimpleOutput() throws FabricPipelinerException {
    //     TrafficTreatment treatment = DefaultTrafficTreatment.builder()
    //             .setOutput(PORT_1)
    //             .build();
    //     PiAction piAction = PiAction.builder()
    //             .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_OUTPUT_SIMPLE)
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.PORT_NUM, PORT_1.toLong()))
    //             .build();
    //     testSimple(treatment, piAction);
    // }
    //
    // /**
    //  * Test program set vlan and output rule for Simple table. Ignored: unsupported.
    //  */
    // @Test
    // public void testSimpleOutputWithVlanTranslation() throws FabricPipelinerException {
    //     TrafficTreatment treatment = DefaultTrafficTreatment.builder()
    //             .setVlanId(VLAN_100)
    //             .setOutput(PORT_1)
    //             .build();
    //     PiAction piAction = PiAction.builder()
    //             .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_OUTPUT_SIMPLE)
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.PORT_NUM, PORT_1.toLong()))
    //             .build();
    //     testSimple(treatment, piAction);
    // }
    //
    // /**
    //  * Test program set mac and output rule for Simple table. Ignored: unsupported now.
    //  */
    // @Test
    // public void testSimpleOutputWithMacTranslation() throws FabricPipelinerException {
    //     TrafficTreatment treatment = DefaultTrafficTreatment.builder()
    //             .setEthSrc(ROUTER_MAC)
    //             .setEthDst(HOST_MAC)
    //             .setOutput(PORT_1)
    //             .build();
    //     PiAction piAction = PiAction.builder()
    //             .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_ROUTING_SIMPLE)
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.SMAC, ROUTER_MAC.toBytes()))
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.DMAC, HOST_MAC.toBytes()))
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.PORT_NUM, PORT_1.toLong()))
    //             .build();
    //     testSimple(treatment, piAction);
    // }
    //
    // /**
    //  * Test program set mac, set vlan, and output rule for Simple table. Ignored: unsupported.
    //  */
    // @Test
    // public void testSimpleOutputWithVlanAndMacTranslation() throws FabricPipelinerException {
    //     TrafficTreatment treatment = DefaultTrafficTreatment.builder()
    //             .setEthSrc(ROUTER_MAC)
    //             .setEthDst(HOST_MAC)
    //             .setVlanId(VLAN_100)
    //             .setOutput(PORT_1)
    //             .build();
    //     PiAction piAction = PiAction.builder()
    //             .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_ROUTING_SIMPLE)
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.SMAC, ROUTER_MAC.toBytes()))
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.DMAC, HOST_MAC.toBytes()))
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.PORT_NUM, PORT_1.toLong()))
    //             .build();
    //     testSimple(treatment, piAction);
    // }
    //
    // private void testSimple(TrafficTreatment treatment, PiAction piAction) throws FabricPipelinerException {
    //     NextObjective nextObjective = DefaultNextObjective.builder()
    //             .withId(NEXT_ID_1)
    //             .withPriority(PRIORITY)
    //             .withMeta(VLAN_META)
    //             .addTreatment(treatment)
    //             .withType(NextObjective.Type.SIMPLE)
    //             .makePermanent()
    //             .fromApp(APP_ID)
    //             .add();
    //
    //     ObjectiveTranslation actualTranslation = translatorSimple.translate(nextObjective);
    //
    //     // Simple table
    //     PiCriterion nextIdCriterion = PiCriterion.builder()
    //             .matchExact(P4InfoConstants.HDR_NEXT_ID, NEXT_ID_1)
    //             .build();
    //     TrafficSelector nextIdSelector = DefaultTrafficSelector.builder()
    //             .matchPi(nextIdCriterion)
    //             .build();
    //     FlowRule expectedFlowRule = DefaultFlowRule.builder()
    //             .forDevice(DEVICE_ID)
    //             .fromApp(APP_ID)
    //             .makePermanent()
    //             // FIXME: currently next objective doesn't support priority, ignore this
    //             .withPriority(0)
    //             .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_SIMPLE)
    //             .withSelector(nextIdSelector)
    //             .withTreatment(DefaultTrafficTreatment.builder()
    //                     .piTableAction(piAction).build())
    //             .build();
    //
    //     ObjectiveTranslation expectedTranslation = ObjectiveTranslation.builder()
    //             .addFlowRule(vlanMetaFlowRule)
    //             .addFlowRule(expectedFlowRule)
    //             .build();
    //
    //     assertEquals(expectedTranslation, actualTranslation);
    // }
    //
    // /**
    //  * Test simple Route and Push Next Objective (set mac, set double vlan and output port).
    //  * Ignored: unsupported.
    //  */
    // @Test
    // public void testSimpleRouteAndPushNextObjective() throws FabricPipelinerException {
    //     TrafficTreatment routeAndPushTreatment = DefaultTrafficTreatment.builder()
    //             .setEthSrc(ROUTER_MAC)
    //             .setEthDst(HOST_MAC)
    //             .setOutput(PORT_1)
    //             .setVlanId(VLAN_100)
    //             .pushVlan()
    //             .setVlanId(VLAN_200)
    //             .build();
    //
    //     NextObjective nextObjective = DefaultNextObjective.builder()
    //             .withId(NEXT_ID_1)
    //             .withPriority(PRIORITY)
    //             .addTreatment(routeAndPushTreatment)
    //             .withType(NextObjective.Type.SIMPLE)
    //             .makePermanent()
    //             .fromApp(APP_ID)
    //             .add();
    //
    //     ObjectiveTranslation actualTranslation = translatorSimple.translate(nextObjective);
    //
    //     PiAction piActionRouting = PiAction.builder()
    //             .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_ROUTING_SIMPLE)
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.SMAC, ROUTER_MAC.toBytes()))
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.DMAC, HOST_MAC.toBytes()))
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.PORT_NUM, PORT_1.toLong()))
    //             .build();
    //
    //     PiAction piActionPush = PiAction.builder()
    //             .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_DOUBLE_VLAN)
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.INNER_VLAN_ID, VLAN_100.toShort()))
    //             .withParameter(new PiActionParam(
    //                     P4InfoConstants.OUTER_VLAN_ID, VLAN_200.toShort()))
    //             .build();
    //
    //
    //     TrafficSelector nextIdSelector = DefaultTrafficSelector.builder()
    //             .matchPi(PiCriterion.builder()
    //                     .matchExact(P4InfoConstants.HDR_NEXT_ID, NEXT_ID_1)
    //                     .build())
    //             .build();
    //     FlowRule expectedFlowRuleRouting = DefaultFlowRule.builder()
    //             .forDevice(DEVICE_ID)
    //             .fromApp(APP_ID)
    //             .makePermanent()
    //             // FIXME: currently next objective doesn't support priority, ignore this
    //             .withPriority(0)
    //             .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_SIMPLE)
    //             .withSelector(nextIdSelector)
    //             .withTreatment(DefaultTrafficTreatment.builder()
    //                     .piTableAction(piActionRouting).build())
    //             .build();
    //     FlowRule expectedFlowRuleDoublePush = DefaultFlowRule.builder()
    //             .withSelector(nextIdSelector)
    //             .withTreatment(DefaultTrafficTreatment.builder()
    //                     .piTableAction(piActionPush)
    //                     .build())
    //             .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_NEXT_VLAN)
    //             .makePermanent()
    //             // FIXME: currently next objective doesn't support priority, ignore this
    //             .withPriority(0)
    //             .forDevice(DEVICE_ID)
    //             .fromApp(APP_ID)
    //             .build();
    //
    //     ObjectiveTranslation expectedTranslation = ObjectiveTranslation.builder()
    //             .addFlowRule(expectedFlowRuleDoublePush)
    //             .addFlowRule(expectedFlowRuleRouting)
    //             .build();
    //
    //
    //     assertEquals(expectedTranslation, actualTranslation);
    // }

    // TODO: re-enable support for xconnext
    // /**
    //  * Test XConnect NextObjective.
    //  *
    //  * @throws FabricPipelinerException
    //  * Ignored: unsupported.
    //  */
    // @Test
    // @Ignore
    // public void testXconnectOutput() throws FabricPipelinerException {
    //     TrafficTreatment treatment1 = DefaultTrafficTreatment.builder()
    //             .setOutput(PORT_1)
    //             .build();
    //     TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
    //             .setOutput(PORT_2)
    //             .build();
    //     NextObjective nextObjective = DefaultNextObjective.builder()
    //             .withId(NEXT_ID_1)
    //             .withPriority(PRIORITY)
    //             .addTreatment(treatment1)
    //             .addTreatment(treatment2)
    //             .withType(NextObjective.Type.BROADCAST)
    //             .makePermanent()
    //             .fromApp(XCONNECT_APP_ID)
    //             .add();
    //
    //     ObjectiveTranslation actualTranslation = translatorHashed.doTranslate(nextObjective);
    //
    //     // Should generate 2 flows for the xconnect table.
    //
    //     // Expected multicast table flow rule.
    //     PiCriterion nextIdCriterion = PiCriterion.builder()
    //             .matchExact(P4InfoConstants.HDR_NEXT_ID, NEXT_ID_1)
    //             .build();
    //     TrafficSelector xcSelector1 = DefaultTrafficSelector.builder()
    //             .matchPi(nextIdCriterion)
    //             .matchInPort(PORT_1)
    //             .build();
    //     TrafficTreatment xcTreatment1 = DefaultTrafficTreatment.builder()
    //             .piTableAction(PiAction.builder()
    //                                    .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_OUTPUT_XCONNECT)
    //                                    .withParameter(new PiActionParam(P4InfoConstants.PORT_NUM, PORT_2.toLong()))
    //                                    .build())
    //             .build();
    //     TrafficSelector xcSelector2 = DefaultTrafficSelector.builder()
    //             .matchPi(nextIdCriterion)
    //             .matchInPort(PORT_2)
    //             .build();
    //     TrafficTreatment xcTreatment2 = DefaultTrafficTreatment.builder()
    //             .piTableAction(PiAction.builder()
    //                                    .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_OUTPUT_XCONNECT)
    //                                    .withParameter(new PiActionParam(P4InfoConstants.PORT_NUM, PORT_1.toLong()))
    //                                    .build())
    //             .build();
    //
    //     FlowRule expectedXcFlowRule1 = DefaultFlowRule.builder()
    //             .forDevice(DEVICE_ID)
    //             .fromApp(XCONNECT_APP_ID)
    //             .makePermanent()
    //             .withPriority(nextObjective.priority())
    //             .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_XCONNECT)
    //             .withSelector(xcSelector1)
    //             .withTreatment(xcTreatment1)
    //             .build();
    //     FlowRule expectedXcFlowRule2 = DefaultFlowRule.builder()
    //             .forDevice(DEVICE_ID)
    //             .fromApp(XCONNECT_APP_ID)
    //             .makePermanent()
    //             .withPriority(nextObjective.priority())
    //             .forTable(P4InfoConstants.FABRIC_INGRESS_NEXT_XCONNECT)
    //             .withSelector(xcSelector2)
    //             .withTreatment(xcTreatment2)
    //             .build();
    //
    //     ObjectiveTranslation expectedTranslation = ObjectiveTranslation.builder()
    //             .addFlowRule(expectedXcFlowRule1)
    //             .addFlowRule(expectedXcFlowRule2)
    //             .build();
    //
    //     assertEquals(expectedTranslation, actualTranslation);
    // }
}
