// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;


import org.easymock.Capture;
import org.easymock.CaptureType;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onosproject.codec.CodecService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.intent.WorkPartitionService;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.onosproject.store.service.StorageService;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;
import org.stratumproject.fabric.tna.behaviour.upf.MockPiPipelineModel;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingException;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;
import org.stratumproject.fabric.tna.slicing.api.TrafficClassDescription;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.onlab.junit.TestTools.assertAfter;
import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_GREEN;
import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_RED;
import static org.stratumproject.fabric.tna.behaviour.Constants.TNA;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_DEFAULT_TC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_QUEUES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR_BITWIDTH;

public class SlicingManagerTest {

    private final SlicingManager manager = new SlicingManager();

    private static final ApplicationId APP_ID =
            new DefaultApplicationId(0, "org.stratumproject.fabric.tna.slicing.test");
    private static final ArrayList<SliceId> SLICE_IDS = new ArrayList<>();
    private static final ArrayList<Device> DEVICES = new ArrayList<>();

    private static final int QOS_FLOW_PRIORITY = 10;
    private static final int DEFAULT_TC_PRIORITY = 10;
    private static final int CLASSIFIER_FLOW_PRIORITY = 0;
    private static final DeviceId DEVICE_ID = DeviceId.deviceId("device:s1");

    private static final QueueId QUEUE_ID_CONTROL = QueueId.of(1);
    private static final QueueId QUEUE_ID_REAL_TIME = QueueId.of(2);
    private static final QueueId QUEUE_ID_ELASTIC = QueueId.of(3);


    private static final TrafficClassDescription TC_CONFIG_CONTROL = new TrafficClassDescription(
            TrafficClass.CONTROL, QUEUE_ID_CONTROL, 0, 0, false);
    private static final TrafficClassDescription TC_CONFIG_REAL_TIME = new TrafficClassDescription(
            TrafficClass.REAL_TIME, QUEUE_ID_REAL_TIME, 0, 0, false);
    private static final TrafficClassDescription TC_CONFIG_ELASTIC = new TrafficClassDescription(
            TrafficClass.ELASTIC, QUEUE_ID_ELASTIC, 0, 0, false);

    private final CoreService coreService = EasyMock.createMock(CoreService.class);
    private final StorageService storageService = EasyMock.createMock(StorageService.class);
    private final DeviceService deviceService = EasyMock.createMock(DeviceService.class);
    private final FlowRuleService flowRuleService = EasyMock.createMock(FlowRuleService.class);
    private final WorkPartitionService workPartitionService = EasyMock.createMock(WorkPartitionService.class);
    private final CodecService codecService = EasyMock.createMock(CodecService.class);
    private final NetworkConfigService nwCfgService = EasyMock.createMock(NetworkConfigService.class);
    private final PiPipeconfService pipeconfService = EasyMock.createMock(PiPipeconfService.class);
    private final Capture<FlowRule> capturedAddedFlowRules = Capture.newInstance(CaptureType.ALL);
    private final Capture<FlowRule> capturedRemovedFlowRules = Capture.newInstance(CaptureType.ALL);

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Before
    public void setup() {
        SLICE_IDS.clear();
        SLICE_IDS.add(SliceId.DEFAULT);
        SLICE_IDS.add(SliceId.of(1));
        SLICE_IDS.add(SliceId.of(2));
        SLICE_IDS.add(SliceId.of(3));
        SLICE_IDS.add(SliceId.of(4));

        DEVICES.clear();
        DEVICES.add(new MockDevice(DEVICE_ID, null));

        String pipeconfId = "mock_pipeconf";
        MockPiPipelineModel pipelineModel =
                new MockPiPipelineModel(Collections.emptyList(),
                        Collections.emptyList(),
                        TNA);
        MockPipeconf mockPipeconf =
                new MockPipeconf(new PiPipeconfId(pipeconfId), pipelineModel);

        manager.appId = APP_ID;
        manager.coreService = coreService;
        manager.storageService = storageService;
        manager.flowRuleService = flowRuleService;
        manager.deviceService = deviceService;
        manager.workPartitionService = workPartitionService;
        manager.codecService = codecService;
        manager.networkCfgService = nwCfgService;
        manager.pipeconfService = pipeconfService;

        EasyMock.expect(coreService.registerApplication(EasyMock.anyObject())).andReturn(APP_ID);
        EasyMock.expect(storageService.<SliceStoreKey, TrafficClassDescription>consistentMapBuilder()).andReturn(
                new MockConsistentMap.Builder<>());
        EasyMock.expect(storageService.<TrafficSelector, SliceStoreKey>consistentMapBuilder()).andReturn(
                new MockConsistentMap.Builder<>());
        EasyMock.expect(storageService.<SliceId, TrafficClass>consistentMapBuilder()).andReturn(
                new MockConsistentMap.Builder<>());
        EasyMock.expect(workPartitionService.isMine(
                EasyMock.anyObject(), EasyMock.anyObject())).andReturn(true).anyTimes();
        EasyMock.expect(deviceService.getAvailableDevices()).andReturn(DEVICES).anyTimes();
        EasyMock.expect(nwCfgService.getConfig(EasyMock.anyObject(), EasyMock.eq(SegmentRoutingDeviceConfig.class)))
                .andReturn(
                        new SegmentRoutingDeviceConfig() {
                @Override
                public Boolean isEdgeRouter() {
                    return true;
                }
            }
        ).anyTimes();
        deviceService.addListener(EasyMock.anyObject());
        EasyMock.expectLastCall();
        flowRuleService.applyFlowRules(EasyMock.capture(capturedAddedFlowRules));
        EasyMock.expectLastCall().anyTimes();
        flowRuleService.removeFlowRules(EasyMock.capture(capturedRemovedFlowRules));
        EasyMock.expectLastCall().anyTimes();
        codecService.registerCodec(EasyMock.anyObject(), EasyMock.anyObject());
        EasyMock.expectLastCall().times(2);
        EasyMock.expect(pipeconfService.getPipeconf(DEVICE_ID)).andReturn(Optional.of(mockPipeconf)).anyTimes();

        EasyMock.replay(coreService, storageService, workPartitionService,
            deviceService, flowRuleService, codecService, nwCfgService, pipeconfService);

        manager.activate();

        EasyMock.verify(coreService, storageService, workPartitionService,
            deviceService, flowRuleService, codecService, nwCfgService, pipeconfService);
    }

    @Test
    public void testAddSlice() {
        // Default slice is automatically pre-provisioned.
        Set<SliceId> expectedSliceIds = new HashSet<>();
        expectedSliceIds.add(SLICE_IDS.get(0));

        // Test adding new slice.
        expectedSliceIds.add(SLICE_IDS.get(1));
        assertTrue(manager.addSlice(SLICE_IDS.get(1)));
        assertEquals(expectedSliceIds, manager.getSlices());

        expectedSliceIds.add(SLICE_IDS.get(2));
        assertTrue(manager.addSlice(SLICE_IDS.get(2)));
        assertEquals(expectedSliceIds, manager.getSlices());

        Set<TrafficClass> expectedTrafficClasses = new HashSet<>();
        expectedTrafficClasses.add(TrafficClass.BEST_EFFORT);
        assertEquals(expectedTrafficClasses, manager.getTrafficClasses(SLICE_IDS.get(0)));
        assertEquals(expectedTrafficClasses, manager.getTrafficClasses(SLICE_IDS.get(1)));
        assertEquals(expectedTrafficClasses, manager.getTrafficClasses(SLICE_IDS.get(2)));

        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(0)));
        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(1)));
        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(2)));
    }

    @Test
    public void testAddSliceExceptionDefaultSlice() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Adding the default slice is not allowed");
        manager.addSlice(SLICE_IDS.get(0));
    }

    @Test
    public void testAddSliceExceptionAlreadyExists() {
        manager.addSlice(SLICE_IDS.get(1));

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Slice 1 already exists");
        manager.addSlice(SLICE_IDS.get(1));
    }

    @Test
    public void testRemoveSlice() {
        Set<SliceId> expectedSliceIds = new HashSet<>();
        expectedSliceIds.add(SLICE_IDS.get(0));
        expectedSliceIds.add(SLICE_IDS.get(1));
        expectedSliceIds.add(SLICE_IDS.get(2));
        manager.addSlice(SLICE_IDS.get(1));
        manager.addSlice(SLICE_IDS.get(2));

        expectedSliceIds.remove(SLICE_IDS.get(1));
        assertTrue(manager.removeSlice(SLICE_IDS.get(1)));
        assertEquals(expectedSliceIds, manager.getSlices());

        assertEquals(1, manager.getTrafficClasses(SLICE_IDS.get(0)).size());
        assertNotNull(manager.getDefaultTrafficClass(SLICE_IDS.get(0)));
        assertEquals(0, manager.getTrafficClasses(SLICE_IDS.get(1)).size());
        assertNull(manager.getDefaultTrafficClass(SLICE_IDS.get(1)));
        assertEquals(1, manager.getTrafficClasses(SLICE_IDS.get(2)).size());
        assertNotNull(manager.getDefaultTrafficClass(SLICE_IDS.get(2)));

        expectedSliceIds.remove(SLICE_IDS.get(2));
        assertTrue(manager.removeSlice(SLICE_IDS.get(2)));
        assertEquals(expectedSliceIds, manager.getSlices());

        assertEquals(0, manager.getTrafficClasses(SLICE_IDS.get(2)).size());
        assertNull(manager.getDefaultTrafficClass(SLICE_IDS.get(2)));
    }

    @Test
    public void testRemoveSliceExceptionDefault() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Removing the default slice is not allowed");
        manager.removeSlice(SLICE_IDS.get(0));
    }

    @Test
    public void testRemoveSliceExceptionNonExistent() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove non-existent slice 1");
        manager.removeSlice(SLICE_IDS.get(1));
    }

    @Test
    public void testAddTrafficClass() {
        Set<TrafficClass> expectedTcs = new HashSet<>();
        expectedTcs.add(TrafficClass.BEST_EFFORT);
        manager.addSlice(SLICE_IDS.get(1));

        // Normal
        expectedTcs.add(TrafficClass.CONTROL);
        assertTrue(manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_CONTROL));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        expectedTcs.add(TrafficClass.REAL_TIME);
        assertTrue(manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_REAL_TIME));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        expectedTcs.add(TrafficClass.ELASTIC);
        assertTrue(manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_ELASTIC));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));
    }

    @Test
    public void testAddTrafficClassExceptionNonExistentSlice() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot add traffic class to non-existent slice 1");
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClassDescription.BEST_EFFORT);
    }

    @Test
    public void testAddTrafficClassExceptionAlreadyExists() {
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_CONTROL);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("TC CONTROL is already allocated for slice 1");
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_CONTROL);
    }

    @Test
    public void testRemoveTrafficClass() {
        Set<TrafficClass> expectedTcs = new HashSet<>();
        expectedTcs.add(TrafficClass.BEST_EFFORT);
        expectedTcs.add(TrafficClass.CONTROL);
        expectedTcs.add(TrafficClass.REAL_TIME);
        expectedTcs.add(TrafficClass.ELASTIC);
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_CONTROL);
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_REAL_TIME);
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_ELASTIC);

        expectedTcs.remove(TrafficClass.CONTROL);
        assertTrue(manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        expectedTcs.remove(TrafficClass.REAL_TIME);
        assertTrue(manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        expectedTcs.remove(TrafficClass.ELASTIC);
        assertTrue(manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.ELASTIC));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));
    }

    @Test
    public void testRemoveTrafficClassExceptionNonExistentSlice() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove a traffic class from non-existent slice 1");
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
    }

    @Test
    public void testRemoveTrafficClassExceptionBestEffort() {
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_CONTROL);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove BEST_EFFORT traffic class from any slice");
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
    }

    @Test
    public void testRemoveTrafficClassExceptionNotAllocated() {
        manager.addSlice(SLICE_IDS.get(1));

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Traffic class CONTROL has not been allocated for slice 1");
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
    }

    @Test
    public void testSetDefaultTrafficClass() {
        manager.addSlice(SLICE_IDS.get(1));

        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(1)));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_CONTROL);
        manager.setDefaultTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        assertEquals(TrafficClass.CONTROL, manager.getDefaultTrafficClass(SLICE_IDS.get(1)));
    }

    @Test
    public void testRemoveTrafficClassExceptionDefaultTc() {
        manager.addTrafficClass(SLICE_IDS.get(0), TC_CONFIG_CONTROL);
        manager.setDefaultTrafficClass(SLICE_IDS.get(0), TrafficClass.CONTROL);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove CONTROL from slice 0 while it is " +
                "being used as the default traffic class");
        manager.removeTrafficClass(SLICE_IDS.get(0), TrafficClass.CONTROL);
    }

    @Test
    public void testAddClassifierFlow() {
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_REAL_TIME);

        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        assertEquals(1, manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).size());
        assertTrue(manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).contains(selector));
    }

    @Test
    public void testAddClassifierFlowExceptionEmptySelector() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Empty traffic selector is not allowed");
        manager.addClassifierFlow(DefaultTrafficSelector.builder().build(),
                SLICE_IDS.get(1), TrafficClass.REAL_TIME);
    }

    @Test
    public void testAddClassifierFlowExceptionWrongSelector() {
        TrafficSelector wrongSelector = DefaultTrafficSelector.builder().matchEthDst(MacAddress.IPV4_MULTICAST).build();
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Selector can only express a match on the L3-L4 5-tuple fields");
        manager.addClassifierFlow(wrongSelector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
    }

    @Test
    public void testRemoveClassifierFlow() {
        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_REAL_TIME);
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);

        assertEquals(1, manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).size());
        manager.removeClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        assertEquals(0, manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).size());
    }

    @Test
    public void testRemoveClassifierFlowException() {
        // Preparation
        TrafficSelector wrongSelector = DefaultTrafficSelector.builder().matchTcpDst(TpPort.tpPort(100)).build();

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("There is no such Flow Classifier Rule " +
                "DefaultTrafficSelector{criteria=[TCP_DST:100]} for slice 1 and TC REAL_TIME");
        manager.removeClassifierFlow(wrongSelector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
    }

    @Test
    public void testRemoveTcWithClassifierFlowException() {
        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_REAL_TIME);
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove REAL_TIME from slice 1 with 1 classifier flow rules");
        assertFalse(manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME));
    }

    @Test
    public void testRemoveSliceWithClassifierFlowException() {
        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_REAL_TIME);
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove slice 1 with 1 classifier flow rules");
        assertFalse(manager.removeSlice(SLICE_IDS.get(1)));
    }


    @Test
    public void testSliceListener() {
        FlowRule queuesFlowRuleSlice1BestEffort = buildQueuesFlowRuleSlice1BestEffort();
        FlowRule defaultTcFlowRuleSlice1BestEffort = buildDefaultTcFlowRuleSlice1BestEffort();
        FlowRule queuesFlowRuleSlice1ControlGreen = buildQueuesFlowRuleSlice1ControlGreen();
        FlowRule queuesFlowRuleSlice1ControlRed = buildQueuesFlowRuleSlice1ControlRed();
        int numDevices = DEVICES.size();
        flowsPreCheck();

        // Default TC after adding a Slice
        capturedAddedFlowRules.reset();
        manager.addSlice(SLICE_IDS.get(1));
        assertAfter(50, () -> {
            assertEquals(2 * numDevices, capturedAddedFlowRules.getValues().size());
            assertEquals(numDevices, capturedAddedFlowRules.getValues().stream()
                    .filter(flowRule -> flowRule.exactMatch(queuesFlowRuleSlice1BestEffort)).count());
            assertEquals(numDevices, capturedAddedFlowRules.getValues().stream()
                    .filter(flowRule -> flowRule.exactMatch(defaultTcFlowRuleSlice1BestEffort)).count());
        });

        // Adding Control class to slice 1
        capturedAddedFlowRules.reset();
        manager.addTrafficClass(SLICE_IDS.get(1), TC_CONFIG_CONTROL);
        assertAfter(50, () -> {
            assertEquals(2 * numDevices, capturedAddedFlowRules.getValues().size());
            assertTrue(capturedAddedFlowRules.getValues()
                    .stream().anyMatch(f -> f.exactMatch(queuesFlowRuleSlice1ControlGreen)));
            assertTrue(capturedAddedFlowRules.getValues()
                    .stream().anyMatch(f -> f.exactMatch(queuesFlowRuleSlice1ControlRed)));
        });

        // Removing Control class from slice 1
        capturedRemovedFlowRules.reset();
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        assertAfter(50, () -> {
            assertEquals(2 * numDevices, capturedRemovedFlowRules.getValues().size());
            assertTrue(capturedRemovedFlowRules.getValues()
                    .stream().anyMatch(f -> f.exactMatch(queuesFlowRuleSlice1ControlGreen)));
            assertTrue(capturedRemovedFlowRules.getValues()
                    .stream().anyMatch(f -> f.exactMatch(queuesFlowRuleSlice1ControlRed)));
        });
    }

    @Test
    public void testClassifierFlowListener() {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchIPSrc(IpPrefix.valueOf("10.20.30.1/32"))
                .matchIPDst(IpPrefix.valueOf("10.20.30.2/32"))
                .matchIPProtocol((byte) 0x06)
                .matchTcpSrc(TpPort.tpPort(80))
                .matchTcpDst(TpPort.tpPort(1234))
                .build();
        FlowRule expectedFlowRule = buildClassifierFlowRule(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT, selector);
        int numDevices = DEVICES.size();
        flowsPreCheck();

        // Adding flow to slice 1
        capturedAddedFlowRules.reset();
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
        assertAfter(50, () -> {
            assertEquals(numDevices, capturedAddedFlowRules.getValues().size());
            assertTrue(capturedAddedFlowRules.getValues()
                    .stream().anyMatch(f -> f.exactMatch(expectedFlowRule)));
        });

        // Removing flow from slice 1
        capturedRemovedFlowRules.reset();
        manager.removeClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
        assertAfter(50, () -> {
            assertEquals(numDevices, capturedRemovedFlowRules.getValues().size());
            assertTrue(capturedRemovedFlowRules.getValues()
                    .stream().anyMatch(f -> f.exactMatch(expectedFlowRule)));
        });
    }

    private FlowRule buildQueuesFlowRuleSlice1BestEffort() {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                        sliceTcConcat(SLICE_IDS.get(1).id(), TrafficClass.BEST_EFFORT.toInt()));

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, QueueId.BEST_EFFORT.id()));

        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(APP_ID)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();
    }

    private FlowRule buildDefaultTcFlowRuleSlice1BestEffort() {
        PiCriterion piCriterion = PiCriterion.builder()
                .matchTernary(P4InfoConstants.HDR_SLICE_TC, sliceTcConcat(SLICE_IDS.get(1).id(), 0), 0x3C)
                .matchExact(P4InfoConstants.HDR_TC_UNKNOWN, 1)
                .build();
        PiAction piTableAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_DEFAULT_TC)
                .withParameter(new PiActionParam(P4InfoConstants.TC, QueueId.BEST_EFFORT.id()))
                .build();

        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(FABRIC_INGRESS_QOS_DEFAULT_TC)
                .fromApp(APP_ID)
                .withPriority(DEFAULT_TC_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterion).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableAction).build())
                .makePermanent()
                .build();
    }

    private FlowRule buildQueuesFlowRuleSlice1ControlGreen() {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                        sliceTcConcat(SLICE_IDS.get(1).id(), TrafficClass.CONTROL.toInt()))
                .matchTernary(HDR_COLOR, COLOR_GREEN, 1 << HDR_COLOR_BITWIDTH - 1);

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, QUEUE_ID_CONTROL.id()));

        return DefaultFlowRule.builder()
                .forDevice(SlicingManagerTest.DEVICE_ID)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(APP_ID)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();
    }

    private FlowRule buildQueuesFlowRuleSlice1ControlRed() {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                        sliceTcConcat(SLICE_IDS.get(1).id(), TrafficClass.CONTROL.toInt()))
                .matchTernary(HDR_COLOR, COLOR_RED, 1 << HDR_COLOR_BITWIDTH - 1);

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, QueueId.BEST_EFFORT.id()));

        return DefaultFlowRule.builder()
                .forDevice(SlicingManagerTest.DEVICE_ID)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(APP_ID)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();
    }

    private FlowRule buildClassifierFlowRule(SliceId sliceId, TrafficClass tc, TrafficSelector selector) {
        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_SLICE_TC_CLASSIFIER_SET_SLICE_ID_TC)
                .withParameters(Set.of(new PiActionParam(P4InfoConstants.SLICE_ID, sliceId.id()),
                        new PiActionParam(P4InfoConstants.TC, tc.toInt())));

        return DefaultFlowRule.builder()
                .forDevice(DEVICE_ID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_SLICE_TC_CLASSIFIER_CLASSIFIER)
                .fromApp(APP_ID)
                .withPriority(CLASSIFIER_FLOW_PRIORITY)
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();
    }

    private void flowsPreCheck() {
        // We install init flows during start up stage So we do a quick check
        // here as a precondition e.g. sliceExecutor installs slice flows on
        // activation stage, if the tests start immediately, the captured flows
        // may include slice flows (unexpceted).
        assertAfter(100, 250, () -> {
            // Number of init flows is variable.
            // For now we install 2 flows for each device
            assertEquals(2 * DEVICES.size(), capturedAddedFlowRules.getValues().size());
        });
    }
}
