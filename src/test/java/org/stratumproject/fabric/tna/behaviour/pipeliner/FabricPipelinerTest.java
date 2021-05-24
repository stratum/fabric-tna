// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.pipeliner;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.easymock.Capture;
import org.easymock.CaptureType;
import org.junit.Before;
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
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.KRYO;

public class FabricPipelinerTest {

    private static final ApplicationId APP_ID = TestApplicationId.create("FabricPipelinerTest");
    private static final DeviceId DEVICE_ID = DeviceId.deviceId("device:1");
    private static final List<Integer> RECIRC_PORTS = List.of(0x44, 0xc4, 0x144, 0x1c4);
    private static final int DEFAULT_FLOW_PRIORITY = 100;
    private static final int CPU_PORT = 320;
    private static final byte FWD_MPLS = 1;
    private static final byte FWD_IPV4_ROUTING = 2;
    private static final int DEFAULT_VLAN = 4094;
    private static final int PKT_IN_MIRROR_SESSION_ID = 0x210;

    private FabricPipeliner pipeliner;
    private FlowRuleService flowRuleService;
    private GroupService groupService;

    @Before
    public void setup() throws IOException {
        FabricCapabilities capabilities = createMock(FabricCapabilities.class);
        expect(capabilities.cpuPort()).andReturn(Optional.of(CPU_PORT)).anyTimes();
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

    @Test
    public void testInitializePipeline() {
        final Capture<FlowRule> capturedCpuIgVlanRule = newCapture(CaptureType.ALL);
        final Capture<FlowRule> capturedCpuFwdClsRule = newCapture(CaptureType.ALL);
        final List<FlowRule> expectedIgPortVlanRules = Lists.newArrayList();
        final Capture<FlowRule> capturedIgPortVlanRule = newCapture(CaptureType.ALL);
        final List<FlowRule> expectedEgVlanRules = Lists.newArrayList();
        final Capture<FlowRule> capturedEgVlanRule = newCapture(CaptureType.ALL);
        final List<FlowRule> expectedFwdClsIpRules = Lists.newArrayList();
        final Capture<FlowRule> capturedFwdClsIpRules = newCapture(CaptureType.ALL);
        final List<FlowRule> expectedFwdClsMplsRules = Lists.newArrayList();
        final Capture<FlowRule> capturedFwdClsMplsRules = newCapture(CaptureType.ALL);
        // ingress_port_vlan table for cpu port
        final TrafficSelector cpuIgVlanSelector = DefaultTrafficSelector.builder()
                .add(Criteria.matchInPort(PortNumber.portNumber(CPU_PORT)))
                .add(PiCriterion.builder()
                        .matchExact(P4InfoConstants.HDR_VLAN_IS_VALID, ZERO)
                        .build())
                .build();
        final TrafficTreatment cpuIgVlanTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)
                        .withParameter(new PiActionParam(P4InfoConstants.VLAN_ID, DEFAULT_VLAN))
                        .withParameter(new PiActionParam(P4InfoConstants.PORT_TYPE, PORT_TYPE_INTERNAL))
                        .build())
                .build();
        final FlowRule expectedCpuIgVlanRule = DefaultFlowRule.builder()
                .withSelector(cpuIgVlanSelector)
                .withTreatment(cpuIgVlanTreatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN)
                .makePermanent()
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();

        final TrafficSelector cpuFwdClsSelector = DefaultTrafficSelector.builder()
                .matchInPort(PortNumber.portNumber(CPU_PORT))
                .matchPi(PiCriterion.builder()
                        .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, Ethernet.TYPE_IPV4)
                        .build())
                .build();
        final TrafficTreatment cpuFwdClsTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                        .withParameter(new PiActionParam(P4InfoConstants.FWD_TYPE, FWD_IPV4_ROUTING))
                        .build())
                .build();
        final FlowRule expectedCpuFwdClsRule = DefaultFlowRule.builder()
                .withSelector(cpuFwdClsSelector)
                .withTreatment(cpuFwdClsTreatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)
                .makePermanent()
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build();
        flowRuleService.applyFlowRules(
                capture(capturedCpuIgVlanRule),
                capture(capturedCpuFwdClsRule));
        final List<GroupBucket> expectedPacketInCloneGroupBuckets = ImmutableList.of(
            createCloneGroupBucket(DefaultTrafficTreatment.builder()
                    .setOutput(PortNumber.portNumber(CPU_PORT))
                    .build()));
        final GroupDescription expectedPacketInCloneGroup = new DefaultGroupDescription(
                DEVICE_ID, GroupDescription.Type.CLONE,
                new GroupBuckets(expectedPacketInCloneGroupBuckets),
                new DefaultGroupKey(KRYO.serialize(PKT_IN_MIRROR_SESSION_ID)),
                PKT_IN_MIRROR_SESSION_ID, APP_ID);
        final Capture<GroupDescription> capturedCloneGroup = newCapture(CaptureType.FIRST);

        groupService.addGroup(capture(capturedCloneGroup));
        expectLastCall().once();

        RECIRC_PORTS.forEach(port -> {
            // ingress_port_vlan table
            final TrafficSelector ingressPortVlanSelector = DefaultTrafficSelector.builder()
                    .add(Criteria.matchInPort(PortNumber.portNumber(port)))
                    .add(PiCriterion.builder()
                            .matchExact(P4InfoConstants.HDR_VLAN_IS_VALID, ZERO)
                            .build())
                    .build();
            final TrafficTreatment ingressPortVlanTreatment = DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)
                            .withParameter(new PiActionParam(P4InfoConstants.VLAN_ID, DEFAULT_VLAN))
                            .withParameter(new PiActionParam(P4InfoConstants.PORT_TYPE, PORT_TYPE_INTERNAL))
                            .build())
                    .build();
            expectedIgPortVlanRules.add(DefaultFlowRule.builder()
                    .withSelector(ingressPortVlanSelector)
                    .withTreatment(ingressPortVlanTreatment)
                    .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN)
                    .makePermanent()
                    .withPriority(DEFAULT_FLOW_PRIORITY)
                    .forDevice(DEVICE_ID)
                    .fromApp(APP_ID)
                    .build());
            // egress_vlan table
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
            expectedEgVlanRules.add(DefaultFlowRule.builder()
                    .withSelector(egressVlanSelector)
                    .withTreatment(egressVlanTreatment)
                    .forTable(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN)
                    .makePermanent()
                    .withPriority(DEFAULT_FLOW_PRIORITY)
                    .forDevice(DEVICE_ID)
                    .fromApp(APP_ID)
                    .build());
            // fwd_classifier table match IPv4
            final TrafficSelector fwdClassIpv4Selector = DefaultTrafficSelector.builder()
                    .matchInPort(PortNumber.portNumber(port))
                    .matchPi(PiCriterion.builder()
                            .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, Ethernet.TYPE_IPV4)
                            .build())
                    .build();
            final TrafficTreatment fwdClassIpv4Treatment = DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                            .withParameter(new PiActionParam(P4InfoConstants.FWD_TYPE, FWD_IPV4_ROUTING))
                            .build())
                    .build();
            expectedFwdClsIpRules.add(DefaultFlowRule.builder()
                    .withSelector(fwdClassIpv4Selector)
                    .withTreatment(fwdClassIpv4Treatment)
                    .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)
                    .makePermanent()
                    .withPriority(DEFAULT_FLOW_PRIORITY)
                    .forDevice(DEVICE_ID)
                    .fromApp(APP_ID)
                    .build());
            // fwd_classifier table match MPLS
            final TrafficSelector fwdClassMplsSelector = DefaultTrafficSelector.builder()
                    .matchInPort(PortNumber.portNumber(port))
                    .matchEthType(Ethernet.MPLS_UNICAST)
                    .matchPi(PiCriterion.builder()
                            .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, Ethernet.TYPE_IPV4)
                            .build())
                    .build();
            final TrafficTreatment fwdClassMplsTreatment = DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                            .withParameter(new PiActionParam(P4InfoConstants.FWD_TYPE, FWD_MPLS))
                            .build())
                    .build();
            expectedFwdClsMplsRules.add(DefaultFlowRule.builder()
                    .withSelector(fwdClassMplsSelector)
                    .withTreatment(fwdClassMplsTreatment)
                    .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)
                    .makePermanent()
                    .withPriority(DEFAULT_FLOW_PRIORITY + 10)
                    .forDevice(DEVICE_ID)
                    .fromApp(APP_ID)
                    .build());
            flowRuleService.applyFlowRules(
                    capture(capturedIgPortVlanRule),
                    capture(capturedEgVlanRule),
                    capture(capturedFwdClsIpRules),
                    capture(capturedFwdClsMplsRules));
        });

        replay(flowRuleService);
        replay(groupService);
        pipeliner.initializePipeline();

        assertTrue(expectedCpuIgVlanRule.exactMatch(capturedCpuIgVlanRule.getValue()));
        assertTrue(expectedCpuFwdClsRule.exactMatch(capturedCpuFwdClsRule.getValue()));
        assertEquals(expectedPacketInCloneGroup, capturedCloneGroup.getValue());

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

        verify(flowRuleService);
        reset(flowRuleService);
    }
}
