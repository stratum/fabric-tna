// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.inbandtelemetry.IntDeviceConfig;
import org.onosproject.net.behaviour.inbandtelemetry.IntMetadataType;
import org.onosproject.net.behaviour.inbandtelemetry.IntObjective;
import org.onosproject.net.behaviour.inbandtelemetry.IntProgrammable;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.driver.DriverData;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.stratumproject.fabric.tna.PipeconfLoader;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Set;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for fabric INT programmable behaviour.
 */
public class FabricIntProgrammableTest {
    private static final int NODE_SID_IPV4 = 101;
    private static final IpAddress ROUTER_IP = IpAddress.valueOf("10.0.1.254");
    private static final String SR_CONFIG_KEY = "segmentrouting";
    private static final ApplicationId APP_ID =
            TestApplicationId.create(PipeconfLoader.APP_NAME);
    private static final DeviceId DEVICE_ID = DeviceId.deviceId("device:1");
    private static final IpPrefix IP_SRC = IpPrefix.valueOf("10.0.0.1/24");
    private static final IpPrefix IP_DST = IpPrefix.valueOf("10.0.0.2/24");
    private static final TpPort L4_SRC = TpPort.tpPort(30000);
    private static final TpPort L4_DST = TpPort.tpPort(32767);
    private static final int DEFAULT_PRIORITY = 10000;
    private static final IpAddress COLLECTOR_IP = IpAddress.valueOf("10.128.0.1");
    private static final TpPort COLLECTOR_PORT = TpPort.tpPort(32766);
    private static final int DEFAULT_QMASK = 0xffff0000;

    private FabricIntProgrammable intProgrammable;
    private FabricCapabilities capabilities;
    private FlowRuleService flowRuleService;
    private GroupService groupService;
    private NetworkConfigService netcfgService;
    private CoreService coreService;

    @Before
    public void setup() throws IOException {
        capabilities = createNiceMock(FabricCapabilities.class);
        expect(capabilities.hasHashedTable()).andReturn(true).anyTimes();
        expect(capabilities.supportDoubleVlanTerm()).andReturn(false).anyTimes();
        expect(capabilities.hwPipeCount()).andReturn(4).anyTimes();
        replay(capabilities);

        // Segment routing config.
        SegmentRoutingDeviceConfig srCfg = new SegmentRoutingDeviceConfig();
        InputStream jsonStream = getClass().getResourceAsStream("/sr.json");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(jsonStream);
        srCfg.init(DEVICE_ID, SR_CONFIG_KEY, jsonNode, mapper, config -> { });

        // Services mock
        flowRuleService = createNiceMock(FlowRuleService.class);
        groupService = createNiceMock(GroupService.class);
        netcfgService = createNiceMock(NetworkConfigService.class);
        coreService = createNiceMock(CoreService.class);
        expect(coreService.getAppId(anyString())).andReturn(APP_ID).anyTimes();
        expect(netcfgService.getConfig(DEVICE_ID, SegmentRoutingDeviceConfig.class))
                .andReturn(srCfg).anyTimes();
        replay(coreService, netcfgService);

        DriverHandler driverHandler = createNiceMock(DriverHandler.class);
        expect(driverHandler.get(FlowRuleService.class)).andReturn(flowRuleService).anyTimes();
        expect(driverHandler.get(GroupService.class)).andReturn(groupService).anyTimes();
        expect(driverHandler.get(NetworkConfigService.class)).andReturn(netcfgService).anyTimes();
        expect(driverHandler.get(CoreService.class)).andReturn(coreService).anyTimes();
        replay(driverHandler);

        DriverData driverData = createNiceMock(DriverData.class);
        expect(driverData.deviceId()).andReturn(DEVICE_ID).anyTimes();
        replay(driverData);

        intProgrammable = new FabricIntProgrammable(capabilities);
        TestUtils.setField(intProgrammable, "handler", driverHandler);
        TestUtils.setField(intProgrammable, "data", driverData);

        // Verify that clone groups are correct?
        groupService.addGroup(anyObject());
        expectLastCall().andVoid().times(4);
        replay(groupService);
        assertTrue(intProgrammable.init());
        verify(groupService);
    }

    @After
    public void teardown() {
        reset(flowRuleService, groupService, netcfgService, coreService);
    }

    /**
     * Test "setSourcePort" function of IntProgrammable.
     * Note that we don't implement this functionality in this pipeconf
     * since we only support postcard mode.
     * We should expect the function returns true without installing
     * any table or group entries.
     */
    @Test
    public void testSetSourcePort() {
        assertTrue(intProgrammable.setSourcePort(PortNumber.ANY));
    }

    /**
     * Test "setSinkPort" function of IntProgrammable.
     * Note that we don't implement this functionality in this pipeconf
     * since we only support postcard mode.
     * We should expect the function returns true without installing
     * any table or group entries.
     */
    @Test
    public void testSetSinkPort() {
        assertTrue(intProgrammable.setSinkPort(PortNumber.ANY));
    }

    /**
     * Test "addIntObjective" function of IntProgrammable.
     */
    @Test
    public void testAddIntObjective() {
        // TCP
        IntObjective intObjective = buildIntObjective(IPv4.PROTOCOL_TCP);
        FlowRule expectedFlow = buildExpectedCollectorFlow(IPv4.PROTOCOL_TCP);
        reset(flowRuleService);
        flowRuleService.applyFlowRules(eq(expectedFlow));
        expectLastCall().andVoid().once();
        replay(flowRuleService);
        assertTrue(intProgrammable.addIntObjective(intObjective));
        verify(flowRuleService);

        // UDP
        intObjective = buildIntObjective(IPv4.PROTOCOL_UDP);
        expectedFlow = buildExpectedCollectorFlow(IPv4.PROTOCOL_UDP);
        reset(flowRuleService);
        flowRuleService.applyFlowRules(eq(expectedFlow));
        expectLastCall().andVoid().once();
        replay(flowRuleService);
        assertTrue(intProgrammable.addIntObjective(intObjective));
        verify(flowRuleService);

        // Don't match L4 ports
        intObjective = buildIntObjective(IPv4.PROTOCOL_ICMP);
        expectedFlow = buildExpectedCollectorFlow(IPv4.PROTOCOL_ICMP);
        reset(flowRuleService);
        flowRuleService.applyFlowRules(eq(expectedFlow));
        expectLastCall().andVoid().once();
        replay(flowRuleService);
        assertTrue(intProgrammable.addIntObjective(intObjective));
        verify(flowRuleService);
    }

    /**
     * Test "addIntObjective" function of IntProgrammable with an
     * invalid match criteria.
     */
    @Test
    public void testAddUnsupportedIntObjective() {
        reset(flowRuleService);
        IntObjective intObjective = buildInvalidIntObjective();
        replay(flowRuleService);
        assertFalse(intProgrammable.addIntObjective(intObjective));
        verify(flowRuleService);
    }

    /**
     * Test "removeIntObjective" function of IntProgrammable.
     */
    @Test
    public void testRemoveIntObjective() {
        // TCP
        IntObjective intObjective = buildIntObjective(IPv4.PROTOCOL_TCP);
        FlowRule expectedFlow = buildExpectedCollectorFlow(IPv4.PROTOCOL_TCP);
        reset(flowRuleService);
        flowRuleService.removeFlowRules(eq(expectedFlow));
        expectLastCall().andVoid().once();
        replay(flowRuleService);
        assertTrue(intProgrammable.removeIntObjective(intObjective));
        verify(flowRuleService);

        // UDP
        intObjective = buildIntObjective(IPv4.PROTOCOL_UDP);
        expectedFlow = buildExpectedCollectorFlow(IPv4.PROTOCOL_UDP);
        reset(flowRuleService);
        flowRuleService.removeFlowRules(eq(expectedFlow));
        expectLastCall().andVoid().once();
        replay(flowRuleService);
        assertTrue(intProgrammable.removeIntObjective(intObjective));
        verify(flowRuleService);

        // Don't match L4 ports
        intObjective = buildIntObjective(IPv4.PROTOCOL_ICMP);
        expectedFlow = buildExpectedCollectorFlow(IPv4.PROTOCOL_ICMP);
        reset(flowRuleService);
        flowRuleService.removeFlowRules(eq(expectedFlow));
        expectLastCall().andVoid().once();
        replay(flowRuleService);
        assertTrue(intProgrammable.removeIntObjective(intObjective));
        verify(flowRuleService);
    }

    /**
     * Test "setupIntConfig" function of IntProgrammable.
     */
    @Test
    public void testSetupIntConfig() {
        final IntDeviceConfig intConfig = IntDeviceConfig.builder()
                .enabled(true)
                .withCollectorIp(COLLECTOR_IP)
                .withCollectorPort(COLLECTOR_PORT)
                .withSinkIp(IpAddress.valueOf("10.192.19.180"))
                .withSinkMac(MacAddress.NONE)
                .withCollectorNextHopMac(MacAddress.BROADCAST)
                .build();
        final FlowRule expectedFlow = buildReportFlow();
        final Collection<FlowRule> flowFilterRules = buildFlowReportFilterRules();
        reset(flowRuleService);
        flowRuleService.applyFlowRules(eq(expectedFlow));
        expectLastCall().andVoid().once();
        flowFilterRules.forEach(flowRule -> {
            flowRuleService.applyFlowRules(eq(flowRule));
            expectLastCall().andVoid().once();
        });
        replay(flowRuleService);
        assertTrue(intProgrammable.setupIntConfig(intConfig));
        verify(flowRuleService);
    }

    @Test
    public void testSupportsFunctionality() {
        assertTrue(intProgrammable.supportsFunctionality(IntProgrammable.IntFunctionality.SOURCE));
        assertTrue(intProgrammable.supportsFunctionality(IntProgrammable.IntFunctionality.TRANSIT));
        assertTrue(intProgrammable.supportsFunctionality(IntProgrammable.IntFunctionality.SINK));
    }

    private FlowRule buildReportFlow() {
        final PiActionParam srcMacParam = new PiActionParam(
                P4InfoConstants.SRC_MAC, MacAddress.ZERO.toBytes());
        final PiActionParam nextHopMacParam = new PiActionParam(
                P4InfoConstants.MON_MAC, MacAddress.ZERO.toBytes());
        final PiActionParam srcIpParam = new PiActionParam(
                P4InfoConstants.SRC_IP, ROUTER_IP.toOctets());
        final PiActionParam monIpParam = new PiActionParam(
                P4InfoConstants.MON_IP,
                COLLECTOR_IP.toOctets());
        final PiActionParam monPortParam = new PiActionParam(
                P4InfoConstants.MON_PORT,
                COLLECTOR_PORT.toInt());
        final PiAction reportAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_REPORT_ENCAP)
                .withParameter(srcMacParam)
                .withParameter(nextHopMacParam)
                .withParameter(srcIpParam)
                .withParameter(monIpParam)
                .withParameter(monPortParam)
                .build();
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(reportAction)
                .build();
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder()
                        .matchExact(P4InfoConstants.HDR_INT_MIRROR_VALID, 1)
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(APP_ID)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_REPORT)
                .build();
    }

    private Collection<FlowRule> buildFlowReportFilterRules() {
        final Collection<FlowRule> result = Sets.newHashSet();
        // Quantize hop latency rule
        final PiActionParam quantizeVal = new PiActionParam(P4InfoConstants.QMASK, DEFAULT_QMASK);
        final PiAction quantizeAction =
                PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_FLOW_REPORT_FILTER_QUANTIZE)
                        .withParameter(quantizeVal)
                        .build();
        final TrafficTreatment quantizeTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(quantizeAction)
                .build();
        result.add(DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .makePermanent()
                .withPriority(DEFAULT_PRIORITY)
                .withTreatment(quantizeTreatment)
                .fromApp(APP_ID)
                .build());
        // Flow filter rule
        final PiAction dropReportAction =
                PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_FLOW_REPORT_FILTER_DROP_REPORT)
                        .build();
        final TrafficTreatment dropReportTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(dropReportAction)
                .build();
        result.add(DefaultFlowRule.builder()
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_FLOW_REPORT_FILTER_FLOW_FILTER)
                .makePermanent()
                .withPriority(DEFAULT_PRIORITY)
                .withTreatment(dropReportTreatment)
                .forDevice(DEVICE_ID)
                .fromApp(APP_ID)
                .build());
        return result;
    }

    private IntObjective buildIntObjective(byte protocol) {
        TrafficSelector.Builder sBuilder = DefaultTrafficSelector.builder()
                .matchIPSrc(IP_SRC)
                .matchIPDst(IP_DST);

        switch (protocol) {
            case IPv4.PROTOCOL_UDP:
                sBuilder.matchUdpSrc(L4_SRC).matchUdpDst(L4_DST);
                break;
            case IPv4.PROTOCOL_TCP:
                sBuilder.matchTcpSrc(L4_SRC).matchTcpDst(L4_DST);
                break;
            default:
                // do nothing
                break;
        }

        // The metadata type doesn't affect the result, however we still need to pass
        // a non-empty set to the objective since the builder won't allow an empty
        // set of INT metadata types.
        Set<IntMetadataType> metadataTypes = ImmutableSet.of(IntMetadataType.SWITCH_ID);
        return new IntObjective.Builder()
                .withSelector(sBuilder.build())
                .withMetadataTypes(metadataTypes)
                .build();
    }

    private IntObjective buildInvalidIntObjective() {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType((short) 10)
                .build();

        // The metadata type doesn't affect the result, however we still need to pass
        // a non-empty set to the objective since the builder won't allow an empty
        // set of INT metadata types.
        Set<IntMetadataType> metadataTypes = ImmutableSet.of(IntMetadataType.SWITCH_ID);
        return new IntObjective.Builder()
                .withSelector(selector)
                .withMetadataTypes(metadataTypes)
                .build();
    }

    private FlowRule buildExpectedCollectorFlow(byte protocol) {
        // Flow rule that we expected.
        TrafficSelector.Builder expectedSelector = DefaultTrafficSelector.builder();
        expectedSelector.matchIPSrc(IP_SRC);
        expectedSelector.matchIPDst(IP_DST);
        if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
            expectedSelector.matchPi(
                    PiCriterion.builder().matchRange(
                            P4InfoConstants.HDR_L4_SPORT,
                            L4_SRC.toInt(),
                            L4_SRC.toInt())
                            .build());
            expectedSelector.matchPi(
                    PiCriterion.builder().matchRange(
                            P4InfoConstants.HDR_L4_DPORT,
                            L4_DST.toInt(),
                            L4_DST.toInt())
                            .build());
        }

        PiAction expectedPiAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_INIT_METADATA)
                .withParameter(new PiActionParam(P4InfoConstants.SWITCH_ID, NODE_SID_IPV4))
                .build();
        TrafficTreatment expectedTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(expectedPiAction)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .withSelector(expectedSelector.build())
                .withTreatment(expectedTreatment)
                .fromApp(APP_ID)
                .withPriority(DEFAULT_PRIORITY)
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_WATCHLIST)
                .makePermanent()
                .build();
    }
}
