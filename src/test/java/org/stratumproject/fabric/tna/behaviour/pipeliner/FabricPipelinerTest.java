// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.pipeliner;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.easymock.Capture;
import org.easymock.CaptureType;
import org.junit.Test;
import org.onlab.packet.Ethernet;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;
import java.util.Optional;

import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.newCapture;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;
import static org.stratumproject.fabric.tna.behaviour.Constants.PORT_TYPE_INTERNAL;
import static org.stratumproject.fabric.tna.behaviour.Constants.ZERO;
import static org.stratumproject.fabric.tna.behaviour.Constants.RECIRC_PORTS;
import static org.stratumproject.fabric.tna.behaviour.Constants.PKT_IN_MIRROR_SESSION_ID;
import static org.stratumproject.fabric.tna.behaviour.Constants.DEFAULT_VLAN;
import static org.stratumproject.fabric.tna.behaviour.Constants.FWD_MPLS;
import static org.stratumproject.fabric.tna.behaviour.Constants.FWD_IPV4_ROUTING;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.KRYO;

public class FabricPipelinerTest {

    private static final ApplicationId APP_ID = TestApplicationId.create("FabricPipelinerTest");
    private static final DeviceId DEVICE_ID = DeviceId.deviceId("device:1");
    private static final int DEFAULT_FLOW_PRIORITY = 100;
    private static final int CPU_PORT = 320;

    private FabricPipeliner pipeliner;
    private FlowRuleService flowRuleService;
    private GroupService groupService;

    private void setup(boolean isBmv2) {
        // Common setup between TNA and bmv2
        FabricCapabilities capabilities = createMock(FabricCapabilities.class);
        expect(capabilities.cpuPort()).andReturn(Optional.of(CPU_PORT)).anyTimes();
        expect(capabilities.isArchBmv2()).andReturn(isBmv2).anyTimes();
        expect(capabilities.isArchTna()).andReturn(!isBmv2).anyTimes();
        replay(capabilities);

        // Services mock
        flowRuleService = createMock(FlowRuleService.class);
        groupService = createMock(GroupService.class);

        pipeliner = new FabricPipeliner(capabilities);
        pipeliner.flowRuleService = flowRuleService;
        pipeliner.groupService = groupService;
        pipeliner.appId = APP_ID;
        pipeliner.deviceId = DEVICE_ID;
    }

    private FlowRule switchInfoRule() {
        final TrafficTreatment setSwitchInfoTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_EGRESS_PKT_IO_EGRESS_SET_SWITCH_INFO)
                        .withParameter(new PiActionParam(P4InfoConstants.CPU_PORT, CPU_PORT))
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .withTreatment(setSwitchInfoTreatment)
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .fromApp(APP_ID)
                .makePermanent()
                .forTable(P4InfoConstants.FABRIC_EGRESS_PKT_IO_EGRESS_SWITCH_INFO)
                .build();
    }

    private FlowRule buildIngressVlanRule(int port) {
        final TrafficSelector cpuIgVlanSelector = DefaultTrafficSelector.builder()
        .add(Criteria.matchInPort(PortNumber.portNumber(port)))
        .add(PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_VLAN_IS_VALID, ZERO)
                .build())
        .build();
        final TrafficTreatment igVlanTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)
                        .withParameter(new PiActionParam(P4InfoConstants.VLAN_ID, DEFAULT_VLAN))
                        .withParameter(new PiActionParam(P4InfoConstants.PORT_TYPE, PORT_TYPE_INTERNAL))
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(cpuIgVlanSelector)
                .withTreatment(igVlanTreatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN)
                .makePermanent()
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    private FlowRule buildEgressVlanRule(int port) {
        final TrafficSelector egressVlanSelector = DefaultTrafficSelector.builder()
        .add(PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_VLAN_ID, DEFAULT_VLAN)
                .matchExact(P4InfoConstants.HDR_EG_PORT, port)
                .build())
        .build();
        final TrafficTreatment egressVlanTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_POP_VLAN)
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(egressVlanSelector)
                .withTreatment(egressVlanTreatment)
                .forTable(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN)
                .makePermanent()
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    private FlowRule buildFwdClsRule(int port, Short etherType, short ipEtherType, byte fwdType, int priority) {
        final TrafficSelector.Builder fwdClsSelector = DefaultTrafficSelector.builder()
                .matchInPort(PortNumber.portNumber(port))
                .matchPi(PiCriterion.builder()
                        .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, ipEtherType)
                        .build());
        if (etherType != null) {
            fwdClsSelector.matchEthType(etherType);
        }
        final TrafficTreatment cpuFwdClsTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                        .withParameter(new PiActionParam(P4InfoConstants.FWD_TYPE, fwdType))
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(fwdClsSelector.build())
                .withTreatment(cpuFwdClsTreatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)
                .makePermanent()
                .withPriority(priority)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
    }

    private GroupDescription buildPacketInCloneGroup() {
        final List<GroupBucket> expectedPacketInCloneGroupBuckets = ImmutableList.of(
                createCloneGroupBucket(DefaultTrafficTreatment.builder()
                        .setOutput(PortNumber.CONTROLLER)
                        .build()));
            return new DefaultGroupDescription(
                    DEVICE_ID, GroupDescription.Type.CLONE,
                    new GroupBuckets(expectedPacketInCloneGroupBuckets),
                    new DefaultGroupKey(KRYO.serialize(PKT_IN_MIRROR_SESSION_ID)),
                    PKT_IN_MIRROR_SESSION_ID, APP_ID);
    }

    private void testInitializePipeline(boolean isBmv2) {
        final Capture<FlowRule> capturedSwitchInfoRule = newCapture(CaptureType.ALL);
        final Capture<FlowRule> capturedCpuIgVlanRule = newCapture(CaptureType.ALL);
        final Capture<FlowRule> capturedCpuFwdClsRule = newCapture(CaptureType.ALL);
        final Capture<FlowRule> capturedIgPortVlanRule = newCapture(CaptureType.ALL);
        final Capture<FlowRule> capturedEgVlanRule = newCapture(CaptureType.ALL);
        final Capture<FlowRule> capturedFwdClsIpRules = newCapture(CaptureType.ALL);
        final Capture<FlowRule> capturedFwdClsMplsRules = newCapture(CaptureType.ALL);
        final Capture<GroupDescription> capturedCloneGroup = newCapture(CaptureType.FIRST);

        final List<FlowRule> expectedIgPortVlanRules = Lists.newArrayList();
        final List<FlowRule> expectedEgVlanRules = Lists.newArrayList();
        final List<FlowRule> expectedFwdClsIpRules = Lists.newArrayList();
        final List<FlowRule> expectedFwdClsMplsRules = Lists.newArrayList();
        final FlowRule expectedSwitchInfoRule = switchInfoRule();
        final FlowRule expectedCpuIgVlanRule = buildIngressVlanRule(CPU_PORT);
        final FlowRule expectedCpuFwdClsRule =
                buildFwdClsRule(CPU_PORT, null, Ethernet.TYPE_IPV4, FWD_IPV4_ROUTING, DEFAULT_FLOW_PRIORITY);
        final GroupDescription expectedPacketInCloneGroup = buildPacketInCloneGroup();

        flowRuleService.applyFlowRules(
                capture(capturedSwitchInfoRule),
                capture(capturedCpuIgVlanRule),
                capture(capturedCpuFwdClsRule));

        groupService.addGroup(capture(capturedCloneGroup));
        expectLastCall().once();

        if (!isBmv2) {
            RECIRC_PORTS.forEach(port -> {
                expectedIgPortVlanRules.add(buildIngressVlanRule(port));
                expectedEgVlanRules.add(buildEgressVlanRule(port));
                expectedFwdClsIpRules.add(
                        buildFwdClsRule(port, null, Ethernet.TYPE_IPV4, FWD_IPV4_ROUTING, DEFAULT_FLOW_PRIORITY));
                expectedFwdClsMplsRules.add(
                        buildFwdClsRule(port,
                                        Ethernet.MPLS_UNICAST,
                                        Ethernet.TYPE_IPV4,
                                        FWD_MPLS,
                                        DEFAULT_FLOW_PRIORITY + 10));
                flowRuleService.applyFlowRules(
                        capture(capturedIgPortVlanRule),
                        capture(capturedEgVlanRule),
                        capture(capturedFwdClsIpRules),
                        capture(capturedFwdClsMplsRules));
            });
        }

        replay(flowRuleService);
        replay(groupService);
        pipeliner.initializePipeline();

        assertTrue(expectedSwitchInfoRule.exactMatch(capturedSwitchInfoRule.getValue()));
        assertTrue(expectedCpuIgVlanRule.exactMatch(capturedCpuIgVlanRule.getValue()));
        assertTrue(expectedCpuFwdClsRule.exactMatch(capturedCpuFwdClsRule.getValue()));
        assertEquals(expectedPacketInCloneGroup, capturedCloneGroup.getValue());

        if (!isBmv2) {
            for (int i = 0; i < RECIRC_PORTS.size(); i++) {
                FlowRule expectIgPortVlanRule = expectedIgPortVlanRules.get(i);
                FlowRule actualIgPortVlanRule = capturedIgPortVlanRule.getValues().get(i);
                FlowRule expectEgVlanRule = expectedEgVlanRules.get(i);
                FlowRule actualEgVlanRule = capturedEgVlanRule.getValues().get(i);
                FlowRule expectedFwdClsIpRule = expectedFwdClsIpRules.get(i);
                FlowRule actualFwdClsIpRule = capturedFwdClsIpRules.getValues().get(i);
                FlowRule expectedFwdClsMplsRule = expectedFwdClsMplsRules.get(i);
                FlowRule actualFwdClsMplsRule = capturedFwdClsMplsRules.getValues().get(i);
                assertTrue(expectIgPortVlanRule.exactMatch(actualIgPortVlanRule));
                assertEquals(expectEgVlanRule, actualEgVlanRule);
                assertTrue(expectEgVlanRule.exactMatch(actualEgVlanRule));
                assertTrue(expectedFwdClsIpRule.exactMatch(actualFwdClsIpRule));
                assertTrue(expectedFwdClsMplsRule.exactMatch(actualFwdClsMplsRule));
            }
        }

        verify(flowRuleService);
        reset(flowRuleService);
    }

    @Test
    public void testBmv2InitializePipeline() {
        final boolean isBmv2 = true;
        setup(isBmv2);
        testInitializePipeline(isBmv2);
    }

    @Test
    public void testTofinoInitializePipeline() {
        final boolean isBmv2 = false;
        setup(isBmv2);
        testInitializePipeline(isBmv2);
    }

}
