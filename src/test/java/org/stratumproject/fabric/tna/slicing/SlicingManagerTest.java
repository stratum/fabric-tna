// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.easymock.Capture;
import org.easymock.CaptureType;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.onosproject.codec.CodecService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.intent.WorkPartitionService;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.slicing.SliceId;
import org.onosproject.net.slicing.SlicingException;
import org.onosproject.net.slicing.TrafficClass;
import org.onosproject.store.service.StorageService;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;
import org.stratumproject.fabric.tna.slicing.api.Color;
import org.stratumproject.fabric.tna.slicing.api.QueueId;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.onlab.junit.TestTools.assertAfter;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.tcToFabricConstants;
import static org.stratumproject.fabric.tna.behaviour.Constants.DEFAULT_SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.Constants.MAX_SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_QUEUES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR_BITWIDTH;

/**
 * Unit tests of Slicing Manager.
 */
public class SlicingManagerTest {

    private final SlicingManager manager = new SlicingManager();

    private static final ApplicationId APP_ID =
        new DefaultApplicationId(0, "org.stratumproject.fabric.tna.slicing.test");
    private static final ArrayList<SliceId> SLICE_IDS = new ArrayList<>();
    private static final ArrayList<Device> DEVICES = new ArrayList<>();

    private static final int QOS_FLOW_PRIORITY = 10;
    private static final DeviceId DID = DeviceId.deviceId("device:s1");

    private final CoreService coreService = EasyMock.createMock(CoreService.class);
    private final StorageService storageService = EasyMock.createMock(StorageService.class);
    private final DeviceService deviceService = EasyMock.createMock(DeviceService.class);
    private final FlowRuleService flowRuleService = EasyMock.createMock(FlowRuleService.class);
    private final WorkPartitionService workPartitionService = EasyMock.createMock(WorkPartitionService.class);
    private final CodecService codecService = EasyMock.createMock(CodecService.class);
    private final Capture<FlowRule> capturedAddedFlowRules = Capture.newInstance(CaptureType.ALL);
    private final Capture<FlowRule> capturedRemovedFlowRules = Capture.newInstance(CaptureType.ALL);

    @Before
    public void setup() {
        SLICE_IDS.clear();
        SLICE_IDS.add(SliceId.of(DEFAULT_SLICE_ID));
        SLICE_IDS.add(SliceId.of(1));
        SLICE_IDS.add(SliceId.of(2));
        SLICE_IDS.add(SliceId.of(3));

        DEVICES.clear();
        DEVICES.add(new MockDevice(DID, null));

        manager.appId = APP_ID;
        manager.coreService = coreService;
        manager.storageService = storageService;
        manager.flowRuleService = flowRuleService;
        manager.deviceService = deviceService;
        manager.workPartitionService = workPartitionService;
        manager.codecService = codecService;

        EasyMock.expect(coreService.registerApplication(EasyMock.anyObject())).andReturn(APP_ID);
        EasyMock.expect(storageService.<SliceStoreKey, QueueId>consistentMapBuilder()).andReturn(
            new MockConsistentMap.Builder<SliceStoreKey, QueueId>());
        EasyMock.expect(storageService.<QueueId, QueueStoreValue>consistentMapBuilder()).andReturn(
            new MockConsistentMap.Builder<QueueId, QueueStoreValue>());
        EasyMock.expect(workPartitionService.isMine(
            EasyMock.anyObject(), EasyMock.anyObject())).andReturn(true).anyTimes();
        EasyMock.expect(deviceService.getAvailableDevices()).andReturn(DEVICES).anyTimes();
        deviceService.addListener(EasyMock.anyObject());
        EasyMock.expectLastCall();
        flowRuleService.applyFlowRules(EasyMock.capture(capturedAddedFlowRules));
        EasyMock.expectLastCall().anyTimes();
        flowRuleService.removeFlowRules(EasyMock.capture(capturedRemovedFlowRules));
        EasyMock.expectLastCall().anyTimes();
        codecService.registerCodec(EasyMock.anyObject(), EasyMock.anyObject());
        EasyMock.expectLastCall().times(2);
        EasyMock.replay(coreService, storageService, workPartitionService,
            deviceService, flowRuleService, codecService);

        manager.activate();

        EasyMock.verify(coreService, storageService, workPartitionService,
            deviceService, flowRuleService, codecService);
    }

    @Test
    public void testAddSliceNormal() {
        // Preparation
        Set<SliceId> expectedSliceIds = new HashSet<>();
        Set<TrafficClass> expectedTcs = new HashSet<>();
        expectedSliceIds.add(SLICE_IDS.get(0));
        expectedTcs.add(TrafficClass.BEST_EFFORT);

        // Normal
        expectedSliceIds.add(SLICE_IDS.get(1));
        assertTrue(manager.addSlice(SLICE_IDS.get(1)));
        assertEquals(expectedSliceIds, manager.getSlices());

        expectedSliceIds.add(SLICE_IDS.get(2));
        assertTrue(manager.addSlice(SLICE_IDS.get(2)));
        assertEquals(expectedSliceIds, manager.getSlices());

        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(0)));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(2)));
    }

    @Test
    public void testAddSliceAbnormal() {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));

        // Abnormal
        // Cannot add default slice (id 0)
        try {
            manager.addSlice(SLICE_IDS.get(0));
            fail();
        } catch (Exception e) {
            assertEquals(e.getClass(), IllegalArgumentException.class);
        }
        // Duplicate slice (id 1)
        assertFalse(manager.addSlice(SLICE_IDS.get(1)));
        // Invalid slice id
        try {
            manager.addSlice(SliceId.of(MAX_SLICE_ID + 1));
            fail();
        } catch (Exception e) {
            assertEquals(e.getClass(), IllegalArgumentException.class);
        }
    }

    @Test
    public void testRemoveSliceNormal() throws SlicingException {
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
    public void testRemoveSliceAbnormal() {
        // Abnormal
        // Cannot remove default slice (id 0)
        try {
            manager.removeSlice(SLICE_IDS.get(0));
            fail();
        } catch (Exception e) {
            assertEquals(e.getClass(), IllegalArgumentException.class);
        }
        // Slice 1 not exist
        assertFalse(manager.removeSlice(SLICE_IDS.get(1)));
        // Invalid slice id
        try {
            manager.removeSlice(SliceId.of(MAX_SLICE_ID + 1));
            fail();
        } catch (Exception e) {
            assertEquals(e.getClass(), IllegalArgumentException.class);
        }
    }

    @Test
    public void testAddTrafficClassNormal() throws SlicingException {
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
    public void testAddTrafficClassAbnormal() throws SlicingException {
        // Preparation
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);

        // Abnormal
        // Duplicate TC
        assertFalse(manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT));
        assertFalse(manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL));
        // SYSTEM should not be added to any slice
        try {
            manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.SYSTEM);
            fail();
        } catch (Exception e) {
            assertEquals(e.getClass(), SlicingException.class);
        }
        // Slice 2 not exist
        assertFalse(manager.addTrafficClass(SLICE_IDS.get(2), TrafficClass.CONTROL));
    }

    @Test
    public void testRemoveTrafficClassNormal() throws SlicingException {
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

        // Remove BE from slice is equivalent to remove slice
        // if BE is the last TC of that slice
        expectedTcs.remove(TrafficClass.BEST_EFFORT);
        assertTrue(manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT));
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));
    }

    @Test
    public void testRemoveTrafficClassAbnormal() throws SlicingException {
        // Preparation
        Set<TrafficClass> expectedTcs = new HashSet<>();
        expectedTcs.add(TrafficClass.BEST_EFFORT);
        expectedTcs.add(TrafficClass.ELASTIC);
        manager.addSlice(SLICE_IDS.get(1));
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.ELASTIC);

        // Abnormal
        // Other TCs must be removed before we can remove BE
        try {
            manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
            fail();
        } catch (Exception e) {
            assertEquals(e.getClass(), SlicingException.class);
        }
        assertEquals(expectedTcs, manager.getTrafficClasses(SLICE_IDS.get(1)));

        // CONTROL class does not exist in slice 1
        // Slice 2 does not exist
        assertFalse(manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL));
        assertFalse(manager.removeTrafficClass(SLICE_IDS.get(2), TrafficClass.CONTROL));
    }

    @Test
    public void testQueue() throws SlicingException {
        // Preparation
        manager.queueStore.put(QueueId.of(4), new QueueStoreValue(TrafficClass.REAL_TIME, true));
        manager.queueStore.put(QueueId.of(7), new QueueStoreValue(TrafficClass.ELASTIC, true));
        SliceStoreKey key;
        for (int i = 1; i <= 3; i++) {
            manager.addSlice(SLICE_IDS.get(i));
            manager.addTrafficClass(SLICE_IDS.get(i), TrafficClass.CONTROL);
            manager.addTrafficClass(SLICE_IDS.get(i), TrafficClass.REAL_TIME);
            manager.addTrafficClass(SLICE_IDS.get(i), TrafficClass.ELASTIC);
        }

        // All BE should point to same queue
        for (int i = 0; i <= 3; i++) {
            key = new SliceStoreKey(SLICE_IDS.get(i), TrafficClass.BEST_EFFORT);
            assertEquals(QueueId.BEST_EFFORT, manager.getSliceStore().get(key));
        }

        // All Control should point to same queue
        for (int i = 1; i <= 3; i++) {
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
        key = new SliceStoreKey(SLICE_IDS.get(3), TrafficClass.REAL_TIME);
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
    public void testSliceListener() throws SlicingException {
        FlowRule slice1BE1 = buildSlice1BE1();
        FlowRule slice1Control1 = buildSlice1Control1();
        FlowRule slice1Control2 = buildSlice1Control2();

        // Adding BE class to slice 1
        capturedAddedFlowRules.reset();
        manager.addSlice(SLICE_IDS.get(1));
        assertAfter(50, () -> {
            assertEquals(1, capturedAddedFlowRules.getValues().size());
            assertTrue(slice1BE1.exactMatch(capturedAddedFlowRules.getValues().get(0)));
        });

        // Adding Control class to slice 1
        capturedAddedFlowRules.reset();
        manager.addTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        assertAfter(50, () -> {
            assertEquals(2, capturedAddedFlowRules.getValues().size());
            assertTrue(slice1Control1.exactMatch(capturedAddedFlowRules.getValues().get(0)));
            assertTrue(slice1Control2.exactMatch(capturedAddedFlowRules.getValues().get(1)));
        });

        // Removing Control class from slice 1
        capturedRemovedFlowRules.reset();
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.CONTROL);
        assertAfter(50, () -> {
            assertEquals(2, capturedRemovedFlowRules.getValues().size());
            assertTrue(slice1Control1.exactMatch(capturedRemovedFlowRules.getValues().get(0)));
            assertTrue(slice1Control2.exactMatch(capturedRemovedFlowRules.getValues().get(1)));
        });

        // Removing BE class from slice 1
        capturedRemovedFlowRules.reset();
        manager.removeTrafficClass(SLICE_IDS.get(1), TrafficClass.BEST_EFFORT);
        assertAfter(50, () -> {
            assertEquals(1, capturedRemovedFlowRules.getValues().size());
            assertTrue(slice1BE1.exactMatch(capturedRemovedFlowRules.getValues().get(0)));
        });
    }

    private FlowRule buildSlice1BE1() {
        // Hard coded parameters
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                    sliceTcConcat(SLICE_IDS.get(1).id(), tcToFabricConstants(TrafficClass.BEST_EFFORT)));

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

    private FlowRule buildSlice1Control1() {
        // Hard coded parameters
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                    sliceTcConcat(SLICE_IDS.get(1).id(), tcToFabricConstants(TrafficClass.CONTROL)))
                .matchTernary(HDR_COLOR, Color.GREEN.ordinal(), 1 << HDR_COLOR_BITWIDTH - 1);

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, QueueId.CONTROL.id()));

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

    private FlowRule buildSlice1Control2() {
        // Hard coded parameters
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC,
                    sliceTcConcat(SLICE_IDS.get(1).id(), tcToFabricConstants(TrafficClass.CONTROL)))
                .matchTernary(HDR_COLOR, Color.RED.ordinal(), 1 << HDR_COLOR_BITWIDTH - 1);

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
}
