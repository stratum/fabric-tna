// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats;

import junit.framework.TestCase;
import org.easymock.EasyMock;
import org.junit.Before;
import org.onlab.packet.ChassisId;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.cli.net.IpProtocol;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.DefaultDevice;
import org.onosproject.net.DefaultPort;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowEntry;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.store.service.DistributedSet;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_STATS_FLOWS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_STATS_FLOWS;

public class StatisticManagerTest extends TestCase {
    private static final ApplicationId APP_ID =
            new DefaultApplicationId(1, "StatisticManagerTest");

    private static final int ID = 1;
    private static final String SRC_IP = "192.168.1.0/24";
    private static final String DST_IP = "192.168.2.0/24";
    private static final String PROTO_TCP = "TCP";
    private static final short SRC_PORT = 1234;
    private static final short DST_PORT = 5678;
    private static final TrafficSelector SEL = DefaultTrafficSelector.builder()
            .matchIPSrc(IpPrefix.valueOf(SRC_IP))
            .matchIPDst(IpPrefix.valueOf(DST_IP))
            .matchIPProtocol((byte) (0xFF & IpProtocol.parseFromString(PROTO_TCP)))
            .matchTcpSrc(TpPort.tpPort(SRC_PORT))
            .matchTcpDst(TpPort.tpPort(DST_PORT))
            .build();
    private static final StatisticKey S_KEY = StatisticKey.builder()
            .withSelector(SEL)
            .withId(ID)
            .build();
    private static final DeviceId DID = DeviceId.NONE;
    private static final Device DEVICE = new DefaultDevice(
            ProviderId.NONE, DID, Device.Type.SWITCH,
            "mfr", "hwVersion", "swVersion", "serialNumber", new ChassisId());
    private static final PortNumber PORT_NUM = PortNumber.P0;
    private static final Port PORT = new DefaultPort(DEVICE, PORT_NUM, true);

    // Flow rule service
    private static final int LIVE = 100;
    private static final int PACKET = 500;
    private static final int BYTE = 5000;
    private static final PiCriterion IG_PI_CRITERION = PiCriterion.builder()
            .matchExact(P4InfoConstants.HDR_IG_PORT, PORT_NUM.toLong())
            .build();
    private static final PiCriterion EG_PI_CRITERION = PiCriterion.builder()
            .matchExact(P4InfoConstants.HDR_STATS_FLOW_ID, S_KEY.id())
            .matchExact(P4InfoConstants.HDR_EG_PORT, PORT_NUM.toLong())
            .build();
    private static final PiTableAction IG_PI_ACTION = PiAction.builder()
            .withId(P4InfoConstants.FABRIC_INGRESS_STATS_COUNT)
            .withParameter(new PiActionParam(P4InfoConstants.FLOW_ID, S_KEY.id()))
            .build();
    private static final PiTableAction EG_PI_ACTION = PiAction.builder()
            .withId(P4InfoConstants.FABRIC_EGRESS_STATS_COUNT)
            .build();
    private static final TrafficSelector IG_SEL = DefaultTrafficSelector.builder(SEL)
            .matchPi(IG_PI_CRITERION)
            .build();
    private static final TrafficSelector EG_SEL = DefaultTrafficSelector.builder()
            .matchPi(EG_PI_CRITERION)
            .build();
    private static final TrafficTreatment IG_TREAT = DefaultTrafficTreatment.builder()
            .piTableAction(IG_PI_ACTION)
            .build();
    private static final TrafficTreatment EG_TREAT = DefaultTrafficTreatment.builder()
            .piTableAction(EG_PI_ACTION)
            .build();
    private static final FlowRule IG_FLOW_RULE = DefaultFlowRule.builder()
            .forDevice(DID)
            .forTable(FABRIC_INGRESS_STATS_FLOWS)
            .withSelector(IG_SEL)
            .withTreatment(IG_TREAT)
            .fromApp(APP_ID)
            .withPriority(1)
            .makePermanent()
            .build();
    private static final FlowRule EG_FLOW_RULE = DefaultFlowRule.builder()
            .forDevice(DID)
            .forTable(FABRIC_EGRESS_STATS_FLOWS)
            .withSelector(EG_SEL)
            .withTreatment(EG_TREAT)
            .fromApp(APP_ID)
            .withPriority(1)
            .makePermanent()
            .build();
    private static final FlowEntry IG_FLOW_ENTRY =
            new DefaultFlowEntry(IG_FLOW_RULE, FlowEntry.FlowEntryState.ADDED, LIVE, PACKET, BYTE);
    private static final FlowEntry EG_FLOW_ENTRY =
            new DefaultFlowEntry(EG_FLOW_RULE, FlowEntry.FlowEntryState.ADDED, LIVE, PACKET, BYTE);

    // Stat map
    private static final StatisticDataKey D_KEY_IG = StatisticDataKey.builder()
            .withDeviceId(DID)
            .withPortNumber(PORT_NUM)
            .withType(StatisticDataKey.Type.INGRESS)
            .build();
    private static final StatisticDataKey D_KEY_EG = StatisticDataKey.builder()
            .withDeviceId(DID)
            .withPortNumber(PORT_NUM)
            .withType(StatisticDataKey.Type.EGRESS)
            .build();
    private static final StatisticDataValue D_VALUE_IG = StatisticDataValue.builder()
            .withByteCount(BYTE)
            .withPrevByteCount(BYTE)
            .withPacketCount(PACKET)
            .withPrevPacketCount(PACKET)
            .withTimeMs(IG_FLOW_ENTRY.lastSeen())
            .withPrevTimeMs(IG_FLOW_ENTRY.lastSeen())
            .build();
    private static final StatisticDataValue D_VALUE_EG = StatisticDataValue.builder()
            .withByteCount(BYTE)
            .withPrevByteCount(BYTE)
            .withPacketCount(PACKET)
            .withPrevPacketCount(PACKET)
            .withTimeMs(EG_FLOW_ENTRY.lastSeen())
            .withPrevTimeMs(EG_FLOW_ENTRY.lastSeen())
            .build();


    private final DistributedSet<StatisticKey> statsStore = EasyMock.createMock(DistributedSet.class);
    private final DeviceService deviceService = EasyMock.createMock(DeviceService.class);
    private final FlowRuleService flowRuleService = EasyMock.createMock(FlowRuleService.class);
    private final StatisticManager mgr = new StatisticManager();

    @Before
    public void setUp() {
        mgr.appId = APP_ID;
        mgr.statsStore = statsStore;
        mgr.deviceService = deviceService;
        mgr.flowRuleService = flowRuleService;
    }

    public void testAddMonitor() {
        // ID does not exist in the store
        EasyMock.expect(statsStore.stream()).andReturn(Stream.of()).once();
        EasyMock.expect(statsStore.add(S_KEY)).andReturn(true).once();
        EasyMock.replay(statsStore);
        mgr.addMonitor(SEL, ID);
        EasyMock.verify(statsStore);

        // ID already exists in the store
        EasyMock.reset(statsStore);
        EasyMock.expect(statsStore.stream()).andReturn(Stream.of(S_KEY)).once();
        EasyMock.replay(statsStore);
        mgr.addMonitor(SEL, ID);
        EasyMock.verify(statsStore);
    }

    public void testRemoveMonitor() {
        EasyMock.expect(statsStore.remove(S_KEY)).andReturn(true).once();
        EasyMock.replay(statsStore);
        mgr.removeMonitor(SEL, ID);
        EasyMock.verify(statsStore);
    }

    public void testGetMonitors() {
        Set<StatisticKey> mockSet = Set.of(S_KEY);
        EasyMock.expect(statsStore.size()).andReturn(mockSet.size()).once();
        EasyMock.expect(statsStore.iterator()).andReturn(mockSet.iterator()).once();
        EasyMock.replay(statsStore);
        Set<StatisticKey> monitors = mgr.getMonitors();
        assertEquals(mockSet, monitors);
        EasyMock.verify(statsStore);
    }

    public void testBuildFlowRules() {
        EasyMock.expect(deviceService.getAvailableDevices()).andReturn(Set.of(DEVICE)).once();
        EasyMock.expect(deviceService.getPorts(DID)).andReturn(List.of(PORT)).once();
        EasyMock.replay(deviceService);
        List<FlowRule> flowRules = mgr.buildFlowRules(S_KEY);
        assertEquals(2, flowRules.size());
        EasyMock.verify(deviceService);
    }

    public void testInternalStatsCollector() {
        EasyMock.expect(flowRuleService.getFlowEntriesById(APP_ID))
                .andReturn(List.of(IG_FLOW_ENTRY, EG_FLOW_ENTRY)).once();
        EasyMock.expect(statsStore.stream()).andReturn(Stream.of(S_KEY)).once();
        EasyMock.replay(flowRuleService);
        EasyMock.replay(statsStore);

        mgr.statsCollector.run();

        assertEquals(2, mgr.statsMap.get(S_KEY).size());
        assertEquals(D_VALUE_IG, mgr.statsMap.get(S_KEY).get(D_KEY_IG));
        assertEquals(D_VALUE_EG, mgr.statsMap.get(S_KEY).get(D_KEY_EG));
        EasyMock.verify(flowRuleService);
    }

}