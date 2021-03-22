// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.pipeliner;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.stratumproject.fabric.tna.behaviour.Constants.*;

/**
 * Test cases for ForwardingObjectiveTranslator.
 */
public class ForwardingObjectiveTranslatorTest extends AbstractObjectiveTranslatorTest {

    private ForwardingObjectiveTranslator translator;

    @Before
    public void setup() {
        super.doSetup();
        translator = new ForwardingObjectiveTranslator(DEVICE_ID, capabilitiesHashed);
    }

    /**
     * Test versatile flag of forwarding objective with ARP match.
     */
    @Test
    public void testAclArp() {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .punt()
                .build();
        // ARP
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP)
                .build();
        ForwardingObjective fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .withTreatment(treatment)
                .add();

        ObjectiveTranslation result = translator.translate(fwd);

        List<FlowRule> flowRulesInstalled = (List<FlowRule>) result.flowRules();
        List<GroupDescription> groupsInstalled = (List<GroupDescription>) result.groups();
        assertEquals(1, flowRulesInstalled.size());
        assertEquals(0, groupsInstalled.size());

        FlowRule actualFlowRule = flowRulesInstalled.get(0);
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_COPY_TO_CPU)
                .build();
        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder()
                                       .piTableAction(piAction).build())
                .fromApp(APP_ID)
                .build();

        assertTrue(expectedFlowRule.exactMatch(actualFlowRule));
    }

    /**
     * Test versatile flag of forwarding objective with DHCP match.
     */
    @Test
    public void testAclDhcp() {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .wipeDeferred()
                .punt()
                .build();
        // DHCP
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT))
                .matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
                .build();
        ForwardingObjective fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .withTreatment(treatment)
                .add();

        ObjectiveTranslation result = translator.translate(fwd);

        List<FlowRule> flowRulesInstalled = (List<FlowRule>) result.flowRules();
        List<GroupDescription> groupsInstalled = (List<GroupDescription>) result.groups();
        assertEquals(1, flowRulesInstalled.size());
        assertTrue(groupsInstalled.isEmpty());

        FlowRule actualFlowRule = flowRulesInstalled.get(0);
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_PUNT_TO_CPU)
                .build();
        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder()
                                       .piTableAction(piAction).build())
                .fromApp(APP_ID)
                .build();

        assertTrue(expectedFlowRule.exactMatch(actualFlowRule));
    }

    /**
     * Test versatile flag of forwarding objective with next step.
     */
    @Test
    public void testAclNext() {
        // ACL 8-tuples
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        ForwardingObjective fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .nextStep(NEXT_ID_1)
                .add();

        ObjectiveTranslation result = translator.translate(fwd);

        List<FlowRule> flowRulesInstalled = (List<FlowRule>) result.flowRules();
        List<GroupDescription> groupsInstalled = (List<GroupDescription>) result.groups();
        assertEquals(1, flowRulesInstalled.size());
        assertTrue(groupsInstalled.isEmpty());

        FlowRule actualFlowRule = flowRulesInstalled.get(0);
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_SET_NEXT_ID_ACL)
                .withParameter(new PiActionParam(P4InfoConstants.NEXT_ID, NEXT_ID_1))
                .build();
        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder()
                        .piTableAction(piAction).build())
                .fromApp(APP_ID)
                .build();

        assertTrue(expectedFlowRule.exactMatch(actualFlowRule));
    }

    /**
     * Test versatile flag of forwarding objective with next step and isEdge flag.
     */
    @Test
    public void testAclNextWithIsInfra() {
        // ACL 8-tuples
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        TrafficSelector metaSelector = DefaultTrafficSelector.builder()
                .matchMetadata(0)
                .build();
        ForwardingObjective fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .nextStep(NEXT_ID_1)
                .withMeta(metaSelector)
                .add();

        ObjectiveTranslation result = translator.translate(fwd);

        List<FlowRule> flowRulesInstalled = (List<FlowRule>) result.flowRules();
        List<GroupDescription> groupsInstalled = (List<GroupDescription>) result.groups();
        assertEquals(1, flowRulesInstalled.size());
        assertTrue(groupsInstalled.isEmpty());

        FlowRule actualFlowRule = flowRulesInstalled.get(0);
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_SET_NEXT_ID_ACL)
                .withParameter(new PiActionParam(P4InfoConstants.NEXT_ID, NEXT_ID_1))
                .build();
        TrafficSelector expectedSelector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IPV4_UNICAST_ADDR)
                .matchPi(PiCriterion.builder()
                        .matchTernary(P4InfoConstants.HDR_PORT_TYPE, EDGE, ONE)
                        .build())
                .build();
        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(expectedSelector)
                .withTreatment(DefaultTrafficTreatment.builder()
                        .piTableAction(piAction).build())
                .fromApp(APP_ID)
                .build();

        assertTrue(expectedFlowRule.exactMatch(actualFlowRule));

        metaSelector = DefaultTrafficSelector.builder()
                .matchMetadata(1)
                .build();
        fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .nextStep(NEXT_ID_1)
                .withMeta(metaSelector)
                .add();

        result = translator.translate(fwd);

        flowRulesInstalled = (List<FlowRule>) result.flowRules();
        groupsInstalled = (List<GroupDescription>) result.groups();
        assertEquals(1, flowRulesInstalled.size());
        assertTrue(groupsInstalled.isEmpty());

        actualFlowRule = flowRulesInstalled.get(0);
        expectedSelector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IPV4_UNICAST_ADDR)
                .matchPi(PiCriterion.builder()
                        .matchTernary(P4InfoConstants.HDR_PORT_TYPE, INFRA, ONE)
                        .build())
                .build();
        expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(expectedSelector)
                .withTreatment(DefaultTrafficTreatment.builder()
                        .piTableAction(piAction).build())
                .fromApp(APP_ID)
                .build();

        assertTrue(expectedFlowRule.exactMatch(actualFlowRule));
    }

    /**
     * Test versatile flag of forwarding objective with acl drop.
     */
    @Test
    public void testAclDrop() {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .wipeDeferred()
                .build();
        // ACL 8-tuples like
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        ForwardingObjective fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .withTreatment(treatment)
                .add();

        ObjectiveTranslation result = translator.translate(fwd);

        List<FlowRule> flowRulesInstalled = (List<FlowRule>) result.flowRules();
        List<GroupDescription> groupsInstalled = (List<GroupDescription>) result.groups();
        assertEquals(1, flowRulesInstalled.size());
        assertTrue(groupsInstalled.isEmpty());

        FlowRule actualFlowRule = flowRulesInstalled.get(0);
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_DROP)
                .build();
        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder()
                        .piTableAction(piAction).build())
                .fromApp(APP_ID)
                .build();

        assertTrue(expectedFlowRule.exactMatch(actualFlowRule));
    }

    /**
     * Test versatile flag of forwarding objective with acl nop.
     */
    @Test
    public void testAclNop() {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .build();
        // ACL 8-tuples like
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        ForwardingObjective fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .withTreatment(treatment)
                .add();

        ObjectiveTranslation result = translator.translate(fwd);

        List<FlowRule> flowRulesInstalled = (List<FlowRule>) result.flowRules();
        List<GroupDescription> groupsInstalled = (List<GroupDescription>) result.groups();
        assertEquals(1, flowRulesInstalled.size());
        assertTrue(groupsInstalled.isEmpty());

        FlowRule actualFlowRule = flowRulesInstalled.get(0);
        PiAction piAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_NOP_ACL)
                .build();
        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_ACL_ACL)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder()
                        .piTableAction(piAction).build())
                .fromApp(APP_ID)
                .build();

        assertTrue(expectedFlowRule.exactMatch(actualFlowRule));
    }

    /**
     * Test programming L2 unicast rule to bridging table.
     */
    @Test
    public void testL2Unicast() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchVlanId(VLAN_100)
                .matchEthDst(HOST_MAC)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING,
                            buildExpectedSelector(selector), selector, NEXT_ID_1);
    }

    @Test
    public void testL2Broadcast() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchVlanId(VLAN_100)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING,
                            selector, selector, NEXT_ID_1);
    }

    @Test
    public void testIPv4Unicast() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        TrafficSelector expectedSelector = DefaultTrafficSelector.builder()
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4,
                            expectedSelector, selector, NEXT_ID_1);
    }

    @Test
    public void testIPv4UnicastWithNoNextId() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        TrafficSelector expectedSelector = DefaultTrafficSelector.builder()
                .matchIPDst(IPV4_UNICAST_ADDR)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4,
                            expectedSelector, selector, null);
    }

    @Test
    @Ignore
    public void testIPv4Multicast() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchVlanId(VLAN_100)
                .matchIPDst(IPV4_MCAST_ADDR)
                .build();
        TrafficSelector expectedSelector = DefaultTrafficSelector.builder()
                .matchIPDst(IPV4_MCAST_ADDR)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4,
                            expectedSelector, selector, NEXT_ID_1);
    }

    @Test
    @Ignore
    public void testIPv6Unicast() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchIPDst(IPV6_UNICAST_ADDR)
                .build();
        TrafficSelector expectedSelector = DefaultTrafficSelector.builder()
                .matchIPDst(IPV6_UNICAST_ADDR)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V6,
                            expectedSelector, selector, NEXT_ID_1);

    }

    @Test
    @Ignore
    public void testIPv6Multicast() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchVlanId(VLAN_100)
                .matchIPDst(IPV6_MCAST_ADDR)
                .build();
        TrafficSelector expectedSelector = DefaultTrafficSelector.builder()
                .matchIPDst(IPV6_MCAST_ADDR)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V6,
                            expectedSelector, selector, NEXT_ID_1);
    }

    @Test
    public void testMpls() throws FabricPipelinerException {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.MPLS_UNICAST)
                .matchMplsLabel(MPLS_10)
                .matchMplsBos(true)
                .build();
        TrafficSelector expectedSelector = DefaultTrafficSelector.builder()
                .matchMplsLabel(MPLS_10)
                .build();

        PiActionParam nextIdParam = new PiActionParam(P4InfoConstants.NEXT_ID, NEXT_ID_1);
        PiAction setNextIdAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_POP_MPLS_AND_NEXT)
                .withParameter(nextIdParam)
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(setNextIdAction)
                .build();
        testSpecificForward(P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS,
                            expectedSelector, selector, NEXT_ID_1, treatment);
    }

    private void testSpecificForward(PiTableId expectedTableId, TrafficSelector expectedSelector,
                                     TrafficSelector selector, Integer nextId) throws FabricPipelinerException {
        TrafficTreatment setNextIdTreatment;
        if (nextId == null) {
            // Ref: RoutingRulePopulator.java->revokeIpRuleForRouter

            setNextIdTreatment = DefaultTrafficTreatment.builder().
                    piTableAction(PiAction.builder()
                                          .withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_NOP_ROUTING_V4)
                                          .build())
                    .build();
        } else {
            PiActionParam nextIdParam = new PiActionParam(P4InfoConstants.NEXT_ID, nextId);
            PiAction.Builder setNextIdAction = PiAction.builder()
                    .withParameter(nextIdParam);

            if (expectedTableId.equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING)) {
                setNextIdAction.withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_BRIDGING);
            } else if (expectedTableId.equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)) {
                setNextIdAction.withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V4);
            } else if (expectedTableId.equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V6)) {
                setNextIdAction.withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V6);
            }

            setNextIdTreatment = DefaultTrafficTreatment.builder()
                    .piTableAction(setNextIdAction.build())
                    .build();
        }

        testSpecificForward(expectedTableId, expectedSelector, selector, nextId, setNextIdTreatment);

    }

    private void testSpecificForward(PiTableId expectedTableId, TrafficSelector expectedSelector,
                                     TrafficSelector selector, Integer nextId, TrafficTreatment treatment)
            throws FabricPipelinerException {
        ForwardingObjective.Builder fwd = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withPriority(PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .withTreatment(treatment)
                .withFlag(ForwardingObjective.Flag.SPECIFIC);

        if (nextId != null) {
            fwd.nextStep(nextId);
        }

        ObjectiveTranslation actualTranslation = translator.translate(fwd.add());

        FlowRule expectedFlowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(expectedTableId)
                .withPriority(PRIORITY)
                .makePermanent()
                .withSelector(expectedSelector)
                .withTreatment(treatment)
                .fromApp(APP_ID)
                .build();

        ObjectiveTranslation expectedTranslation = ObjectiveTranslation.builder()
                .addFlowRule(expectedFlowRule)
                .build();

        assertEquals(expectedTranslation, actualTranslation);
    }

    private TrafficSelector buildExpectedSelector(TrafficSelector selector) {
        TrafficSelector.Builder sbuilder = DefaultTrafficSelector.builder();
        selector.criteria().forEach(c -> {
            if (c.type() == Criterion.Type.ETH_DST) {
                sbuilder.matchEthDstMasked(((EthCriterion) c).mac(), MacAddress.EXACT_MASK);
            } else {
                sbuilder.add(c);
            }
        });
        return sbuilder.build();
    }
}
