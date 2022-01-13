// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

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
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.onosproject.store.service.StorageService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;
import org.stratumproject.fabric.tna.behaviour.upf.MockPiPipelineModel;
import org.stratumproject.fabric.tna.slicing.api.Color;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingException;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.onlab.junit.TestTools.assertAfter;
import static org.stratumproject.fabric.tna.behaviour.Constants.TNA;
import static org.stratumproject.fabric.tna.behaviour.Constants.V1MODEL;
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
    private static final DeviceId DID = DeviceId.deviceId("device:s1");
    private static final DeviceId DID_BMV2 = DeviceId.deviceId("device:s2");

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

    private FabricCapabilities getCapabilities(DeviceId deviceId) throws RuntimeException {
        Optional<PiPipeconf> pipeconf = pipeconfService.getPipeconf(deviceId);
        return pipeconf
                .map(FabricCapabilities::new)
                .orElseThrow(
                    () -> new RuntimeException("Cannot get capabilities for device " + deviceId.toString()
                ));
    }

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
        DEVICES.add(new MockDevice(DID, null));
        DEVICES.add(new MockDevice(DID_BMV2, null));

        String bmv2PipeconfId = "org.stratumproject.fabric.bmv2";
        String tmPipeconfId = "org.stratumproject.fabric.montara_sde_9_5_0";
        MockPiPipelineModel bmv2PipelineModel =
                new MockPiPipelineModel(Collections.EMPTY_LIST,
                                        Collections.EMPTY_LIST,
                                        V1MODEL);
        MockPiPipelineModel tmPipelineModel =
                new MockPiPipelineModel(Collections.EMPTY_LIST,
                                        Collections.EMPTY_LIST,
                                        TNA);
        MockPipeconf bmv2MockPipeconf =
                new MockPipeconf(new PiPipeconfId(bmv2PipeconfId), bmv2PipelineModel);
        MockPipeconf tmMockPipeconf =
                new MockPipeconf(new PiPipeconfId(tmPipeconfId), tmPipelineModel);

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
        EasyMock.expect(storageService.<SliceStoreKey, QueueId>consistentMapBuilder()).andReturn(
            new MockConsistentMap.Builder<SliceStoreKey, QueueId>());
        EasyMock.expect(storageService.<QueueId, QueueStoreValue>consistentMapBuilder()).andReturn(
            new MockConsistentMap.Builder<QueueId, QueueStoreValue>());
        EasyMock.expect(storageService.<TrafficSelector, SliceStoreKey>consistentMapBuilder()).andReturn(
            new MockConsistentMap.Builder<TrafficSelector, SliceStoreKey>());
        EasyMock.expect(storageService.<SliceId, TrafficClass>consistentMapBuilder()).andReturn(
                new MockConsistentMap.Builder<SliceId, TrafficClass>());
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
        EasyMock.expect(pipeconfService.getPipeconf(DID_BMV2)).andReturn(Optional.of(bmv2MockPipeconf)).anyTimes();
        EasyMock.expect(pipeconfService.getPipeconf(DID)).andReturn(Optional.of(tmMockPipeconf)).anyTimes();

        EasyMock.replay(coreService, storageService, workPartitionService,
            deviceService, flowRuleService, codecService, nwCfgService, pipeconfService);

        manager.activate();

        EasyMock.verify(coreService, storageService, workPartitionService,
            deviceService, flowRuleService, codecService, nwCfgService, pipeconfService);
    }

    @Test
    public void testAddSlice() {
        // Preparation
        Set<SliceId> expectedSliceIds = new HashSet<>();
        expectedSliceIds.add(SLICE_IDS.get(0));

        // Normal
        expectedSliceIds.add(SLICE_IDS.get(1));
        assertTrue(manager.addSlice(SLICE_IDS.get(1)));
        assertEquals(expectedSliceIds, manager.getSlices());

        expectedSliceIds.add(SLICE_IDS.get(2));
        assertTrue(manager.addSlice(SLICE_IDS.get(2)));
        assertEquals(expectedSliceIds, manager.getSlices());

        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(0)));
        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(1)));
        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(2)));
    }

    @Test
    public void testAddSliceException1() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Adding default slice is not allowed");
        manager.addSlice(SLICE_IDS.get(0));
    }

    @Test
    public void testAddSliceException2() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("TC BEST_EFFORT is already allocated for slice 1");
        manager.addSlice(SLICE_IDS.get(1));
    }

    @Test
    public void testRemoveSlice() {
        // Preparation
        Set<SliceId> expectedSliceIds = new HashSet<>();
        expectedSliceIds.add(SLICE_IDS.get(0));
        expectedSliceIds.add(SLICE_IDS.get(1));
        expectedSliceIds.add(SLICE_IDS.get(2));
        manager.addSlice(SLICE_IDS.get(1));
        manager.addSlice(SLICE_IDS.get(2));
        manager.addTrafficClass(SLICE_IDS.get(2), TrafficClass.CONTROL);

        // Normal
        expectedSliceIds.remove(SLICE_IDS.get(1));
        assertTrue(manager.removeSlice(SLICE_IDS.get(1)));
        assertEquals(expectedSliceIds, manager.getSlices());

        expectedSliceIds.remove(SLICE_IDS.get(2));
        assertTrue(manager.removeSlice(SLICE_IDS.get(2)));
        assertEquals(expectedSliceIds, manager.getSlices());
    }

    @Test
    public void testRemoveSliceException1() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Removing default slice is not allowed");
        manager.removeSlice(SLICE_IDS.get(0));
    }

    @Test
    public void testRemoveSliceException2() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove a non-existent slice 1");
        manager.removeSlice(SLICE_IDS.get(1));
    }

    @Test
    public void testAddTrafficClass() {
        // Preparation
        Set<TrafficClass> expectedTcs = new HashSet<>();
        expectedTcs.add(TrafficClass.BEST_EFFORT);
        manager.addSlice(SLICE_IDS.get(1));

        // Normal
        expectedTcs.add(TrafficClass.CONTROL);
        assertTrue(manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        expectedTcs.add(TrafficClass.REAL_TIME);
        assertTrue(manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        expectedTcs.add(TrafficClass.ELASTIC);
        assertTrue(manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.ELASTIC));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        // Add BE to non-existent slice is equivalent to add slice
        expectedTcs = new HashSet<>();
        expectedTcs.add(TrafficClass.BEST_EFFORT);
        assertTrue(manager.addTrafficClass(SLICE_IDS.get(2), TrafficClass.BEST_EFFORT));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(2)));
    }

    @Test
    public void testAddTrafficClassException() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("TC CONTROL is already allocated for slice 1");
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
    }

    @Test
    public void testRemoveTrafficClass() {
        // Preparation
        Set<TrafficClass> expectedTcs = new HashSet<>();
        expectedTcs.add(TrafficClass.BEST_EFFORT);
        expectedTcs.add(TrafficClass.CONTROL);
        expectedTcs.add(TrafficClass.REAL_TIME);
        expectedTcs.add(TrafficClass.ELASTIC);
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.ELASTIC);

        // Normal
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
    public void testRemoveTrafficClassException1() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Can't remove BEST_EFFORT from slice 1 while it is being used as Default TC");
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
    }

    @Test
    public void testRemoveTrafficClassException2() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("TC CONTROL has not been allocated to slice 1");
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
    }

    @Test
    public void testRemoveTrafficClassException3() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Can't remove BEST_EFFORT from slice 0 while it is being used as Default TC");
        manager.removeTrafficClass(SLICE_IDS.get(0), TrafficClass.BEST_EFFORT);
    }

    @Test
    public void testSetDefaultTrafficClass() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));

        assertEquals(TrafficClass.BEST_EFFORT, manager.getDefaultTrafficClass(SLICE_IDS.get(1)));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        manager.setDefaultTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        assertEquals(TrafficClass.CONTROL, manager.getDefaultTrafficClass(SLICE_IDS.get(1)));
    }

    @Test
    public void testSetDefaultTrafficClassException() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Can't set CONTROL as default TC because it has not been allocated to slice 1");
        manager.setDefaultTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
    }

    @Test
    public void testRemoveDefaultTrafficClassException() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        manager.setDefaultTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Can't remove CONTROL from slice 1 while it is being used as Default TC");
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
    }

    @Test
    public void testAddFlowClassifier() {
        // Preparation
        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME);

        // Normal
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        assertEquals(1, manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).size());
        assertTrue(manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).contains(selector));
    }

    @Test
    public void testAddFlowClassifierException1() {
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Empty traffic selector is not allowed");
        manager.addClassifierFlow(DefaultTrafficSelector.builder().build(),
                                    SLICE_IDS.get(1), TrafficClass.REAL_TIME);
    }

    @Test
    public void testAddFlowClassifierException2() {
        // Preparation
        TrafficSelector wrongSelector = DefaultTrafficSelector.builder().matchEthDst(MacAddress.IPV4_MULTICAST).build();

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Only accept 5-tuple DefaultTrafficSelector{criteria=[ETH_DST:01:00:5E:00:00:00]}");
        manager.addClassifierFlow(wrongSelector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
    }

    @Test
    public void testRemoveFlowClassifier() {
        // Preparation
        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);

        // Normal
        assertEquals(1, manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).size());
        manager.removeClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        assertEquals(0, manager.getClassifierFlows(SLICE_IDS.get(1), TrafficClass.REAL_TIME).size());
    }

    @Test
    public void testRemoveFlowClassifierException() {
        // Preparation
        TrafficSelector wrongSelector = DefaultTrafficSelector.builder().matchTcpDst(TpPort.tpPort(100)).build();

        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("There is no such Flow Classifier Rule " +
            "DefaultTrafficSelector{criteria=[TCP_DST:100]} for slice 1 and TC REAL_TIME");
        manager.removeClassifierFlow(wrongSelector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);
    }

    @Test
    public void testRemoveSliceAndTcWithFlowClassifierException1() {
        // Preparation
        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);

        // Fail to remove Slice and TC when Flow Classifier
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove REAL_TIME from slice 1 with 1 Flow Classifier Rules");
        assertFalse(manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME));
    }

    @Test
    public void testRemoveSliceAndTcWithFlowClassifierException2() {
        // Preparation
        TrafficSelector selector = DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(100)).build();
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.REAL_TIME);

        // Fail to remove Slice and TC when Flow Classifier
        exceptionRule.expect(SlicingException.class);
        exceptionRule.expectMessage("Cannot remove slice 1 with 1 Flow Classifier Rules");
        assertFalse(manager.removeSlice(SLICE_IDS.get(1)));
    }

    @Test
    public void testQueue() {
        // Preparation
        manager.queueStore.put(QueueId.of(4), new QueueStoreValue(TrafficClass.REAL_TIME, true));
        manager.queueStore.put(QueueId.of(7), new QueueStoreValue(TrafficClass.ELASTIC, true));
        SliceStoreKey key;
        for (int i = 1; i <= 4; i++) {
            manager.addSlice(SLICE_IDS.get(i));
            manager.addTrafficClass(SLICE_IDS.get(i), TrafficClass.CONTROL);
            // The following actions may throw a slicing exception
            // indicate that there is no available queue
            // We skip the exception here because we are not interested
            // in it (We are testing the assigned queue id).
            try {
                manager.addTrafficClass(SLICE_IDS.get(i), TrafficClass.REAL_TIME);
            } catch (SlicingException e) { }
            try {
                manager.addTrafficClass(SLICE_IDS.get(i), TrafficClass.ELASTIC);
            } catch (SlicingException e) { }
        }

        // All BE should point to same queue
        for (int i = 0; i <= 4; i++) {
            key = new SliceStoreKey(SLICE_IDS.get(i), TrafficClass.BEST_EFFORT);
            assertEquals(QueueId.BEST_EFFORT, manager.getSliceStore().get(key));
        }

        // All Control should point to same queue
        for (int i = 1; i <= 4; i++) {
            key = new SliceStoreKey(SLICE_IDS.get(i), TrafficClass.CONTROL);
            assertEquals(QueueId.CONTROL, manager.getSliceStore().get(key));
        }

        // No slice should point to SYSTEM queue
        assertFalse(manager.getSliceStore().entrySet().stream().anyMatch(e -> e.getValue().equals(QueueId.SYSTEM)));

        // Each REAL TIME class should point to single queue
        // or point to nothing if there is no available queue
        key = new SliceStoreKey(SLICE_IDS.get(1), TrafficClass.REAL_TIME);
        assertEquals(QueueId.of(3), manager.getSliceStore().get(key));
        key = new SliceStoreKey(SLICE_IDS.get(2), TrafficClass.REAL_TIME);
        assertEquals(QueueId.of(4), manager.getSliceStore().get(key));
        key = new SliceStoreKey(SLICE_IDS.get(4), TrafficClass.REAL_TIME);
        assertEquals(null, manager.getSliceStore().get(key));

        // Each ELASTIC class should point to single queue
        // or point to nothing if there is no available queue
        key = new SliceStoreKey(SLICE_IDS.get(1), TrafficClass.ELASTIC);
        assertEquals(QueueId.of(6), manager.getSliceStore().get(key));
        key = new SliceStoreKey(SLICE_IDS.get(2), TrafficClass.ELASTIC);
        assertEquals(QueueId.of(7), manager.getSliceStore().get(key));
        key = new SliceStoreKey(SLICE_IDS.get(3), TrafficClass.ELASTIC);
        assertEquals(null, manager.getSliceStore().get(key));

        // After removing a REAL TIME or ELASTIC class, a queue should be released
        // and ready to be allocated
        manager.removeTrafficClass(SLICE_IDS.get(2), TrafficClass.ELASTIC);
        manager.addTrafficClass(SLICE_IDS.get(3), TrafficClass.ELASTIC);
        key = new SliceStoreKey(SLICE_IDS.get(3), TrafficClass.ELASTIC);
        assertEquals(QueueId.of(7), manager.getSliceStore().get(key));
    }

    @Test
    public void testSliceListener() {
        FlowRule slice1BE1 = buildSlice1BE1();
        FlowRule defaulTc1BE = buildDefaultTc1Be();
        FlowRule slice1Control1 = buildSlice1Control1(DID);
        FlowRule slice1Control2 = buildSlice1Control2(DID, false);
        FlowRule bmv2Slice1Control1 = buildSlice1Control1(DID_BMV2);
        FlowRule bmv2Slice1Control2 = buildSlice1Control2(DID_BMV2, true);
        int numDevices = DEVICES.size();
        flowsPreCheck();

        // Default TC after adding a Slice
        capturedAddedFlowRules.reset();
        manager.addSlice(SLICE_IDS.get(1));
        assertAfter(50, () -> {
            assertEquals(3 * numDevices, capturedAddedFlowRules.getValues().size());
            assertEquals(2, capturedAddedFlowRules.getValues().stream()
                    .filter(flowRule -> flowRule.exactMatch(slice1BE1)).count());
            assertEquals(1, capturedAddedFlowRules.getValues().stream()
                    .filter(flowRule -> flowRule.exactMatch(defaulTc1BE)).count());
        });

        // Adding Control class to slice 1
        capturedAddedFlowRules.reset();
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        assertAfter(50, () -> {
            assertEquals(2 * numDevices, capturedAddedFlowRules.getValues().size());
            assertTrue(capturedAddedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(slice1Control1)));
            assertTrue(capturedAddedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(slice1Control2)));
            assertTrue(capturedAddedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(bmv2Slice1Control1)));
            assertTrue(capturedAddedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(bmv2Slice1Control2)));
        });

        // Removing Control class from slice 1
        capturedRemovedFlowRules.reset();
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        assertAfter(50, () -> {
            assertEquals(2 * numDevices, capturedRemovedFlowRules.getValues().size());
            assertTrue(capturedRemovedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(slice1Control1)));
            assertTrue(capturedRemovedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(slice1Control2)));
            assertTrue(capturedRemovedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(bmv2Slice1Control1)));
            assertTrue(capturedRemovedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(bmv2Slice1Control2)));
        });
    }

    @Test
    public void testFlowListener() {
        FlowRule mock = build5Tuple();
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .matchIPSrc(IpPrefix.valueOf("10.20.30.1/32"))
            .matchIPDst(IpPrefix.valueOf("10.20.30.2/32"))
            .matchIPProtocol((byte) 0x06)
            .matchTcpSrc(TpPort.tpPort(80))
            .matchTcpDst(TpPort.tpPort(1234))
            .build();
        int numDevices = DEVICES.size();
        flowsPreCheck();

        // Adding mock rule to slice 1 BE
        capturedAddedFlowRules.reset();
        manager.addClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
        assertAfter(50, () -> {
            assertEquals(1 * numDevices, capturedAddedFlowRules.getValues().size());
            assertTrue(capturedAddedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(mock)));
        });

        // Removing mock rule from slice 1 BE
        capturedRemovedFlowRules.reset();
        manager.removeClassifierFlow(selector, SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
        assertAfter(50, () -> {
            assertEquals(1 * numDevices, capturedRemovedFlowRules.getValues().size());
            assertTrue(capturedRemovedFlowRules.getValues()
                        .stream().anyMatch(f -> f.exactMatch(mock)));
        });
    }

    private FlowRule buildSlice1BE1() {
        // Hard coded parameters
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                    sliceTcConcat(SLICE_IDS.get(1).id(), TrafficClass.BEST_EFFORT.ordinal()));

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, QueueId.BEST_EFFORT.id()));

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(DID)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(APP_ID)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        return flowRule;
    }

    private FlowRule buildDefaultTc1Be() {
        // Hard coded parameters
        PiCriterion piCriterion = PiCriterion.builder()
                .matchTernary(P4InfoConstants.HDR_SLICE_TC, sliceTcConcat(SLICE_IDS.get(1).id(), 0), 0x3C)
                .matchExact(P4InfoConstants.HDR_TC_UNKNOWN, 1)
                .build();
        PiAction piTableAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_DEFAULT_TC)
                .withParameter(new PiActionParam(P4InfoConstants.TC, QueueId.BEST_EFFORT.id()))
                .build();
        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(DID)
                .forTable(FABRIC_INGRESS_QOS_DEFAULT_TC)
                .fromApp(APP_ID)
                .withPriority(DEFAULT_TC_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterion).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableAction).build())
                .makePermanent()
                .build();

        return flowRule;
    }

    private FlowRule buildSlice1Control1(DeviceId deviceId) {
        // Hard coded parameters
        int colorGreen = getCapabilities(deviceId).getMeterColor(Color.GREEN);

        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                    sliceTcConcat(SLICE_IDS.get(1).id(), TrafficClass.CONTROL.ordinal()))
                .matchTernary(HDR_COLOR, colorGreen, 1 << HDR_COLOR_BITWIDTH - 1);

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, QueueId.CONTROL.id()));

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(APP_ID)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        return flowRule;
    }

    private FlowRule buildSlice1Control2(DeviceId deviceId, boolean isBmv2) {
        // Hard coded parameters

        int colorRed = getCapabilities(deviceId).getMeterColor(Color.RED);

        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                    sliceTcConcat(SLICE_IDS.get(1).id(), TrafficClass.CONTROL.ordinal()))
                .matchTernary(HDR_COLOR, colorRed, 1 << HDR_COLOR_BITWIDTH - 1);

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, QueueId.BEST_EFFORT.id()));

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(APP_ID)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        return flowRule;
    }

    private FlowRule build5Tuple() {
        // Hard coded parameters
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .matchIPSrc(IpPrefix.valueOf("10.20.30.1/32"))
            .matchIPDst(IpPrefix.valueOf("10.20.30.2/32"))
            .matchIPProtocol((byte) 0x06)
            .matchTcpSrc(TpPort.tpPort(80))
            .matchTcpDst(TpPort.tpPort(1234))
            .build();

        return buildClassifierFromSelector(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT, selector);
    }

    private FlowRule buildClassifierFromSelector(SliceId sliceId, TrafficClass tc, TrafficSelector selector) {
        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_SLICE_TC_CLASSIFIER_SET_SLICE_ID_TC)
                .withParameters(Set.of(new PiActionParam(P4InfoConstants.SLICE_ID, sliceId.id()),
                                       new PiActionParam(P4InfoConstants.TC, tc.ordinal())));

        return DefaultFlowRule.builder()
                .forDevice(DID)
                .forTable(P4InfoConstants.FABRIC_INGRESS_SLICE_TC_CLASSIFIER_CLASSIFIER)
                .fromApp(APP_ID)
                .withPriority(CLASSIFIER_FLOW_PRIORITY)
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();
    }

    private void flowsPreCheck() {
        // We install init flows during start up stage
        // So we do a quick check here as a precondition
        // e.g. sliceExecutor installs slice flows on activation stage, if the tests start immediately,
        // the captured flows may include slice flows (unexpceted).
        assertAfter(100, 250, () -> {
            // Number of init flows are variant
            // For now we install 2 flows for each device
            assertEquals(2 * DEVICES.size(), capturedAddedFlowRules.getValues().size());
        });
    }
}
