// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;
import org.onlab.util.KryoNamespace;
import org.onosproject.codec.CodecService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.intent.WorkPartitionService;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;
import org.stratumproject.fabric.tna.slicing.api.MeterColor;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingAdminService;
import org.stratumproject.fabric.tna.slicing.api.SlicingException;
import org.stratumproject.fabric.tna.slicing.api.SlicingProviderService;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;
import org.stratumproject.fabric.tna.slicing.api.TrafficClassDescription;
import org.stratumproject.fabric.tna.web.SliceIdCodec;
import org.stratumproject.fabric.tna.web.TrafficClassCodec;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.fiveTupleOnly;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_DEFAULT_TC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_QUEUES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR_BITWIDTH;
import static org.stratumproject.fabric.tna.slicing.api.SlicingException.Type.FAILED;
import static org.stratumproject.fabric.tna.slicing.api.SlicingException.Type.INVALID;
import static org.stratumproject.fabric.tna.slicing.api.SlicingException.Type.UNSUPPORTED;

/**
 * Implementation of SlicingService.
 */
@Component(immediate = true, service = {
        SlicingService.class,
        SlicingAdminService.class
})
public class SlicingManager implements SlicingService, SlicingProviderService, SlicingAdminService {
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected WorkPartitionService workPartitionService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CodecService codecService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService networkCfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PiPipeconfService pipeconfService;


    private static final Logger log = getLogger(SlicingManager.class);
    private static final String APP_NAME = "org.stratumproject.fabric.tna.slicing"; // TODO revisit naming
    private static final int QOS_FLOW_PRIORITY = 10;
    private static final int DEFAULT_TC_PRIORITY = 10;

    // We use the lowest priority to avoid overriding the port-based trust_dscp rules installed
    // when translating filtering objectives.
    private static final int CLASSIFIER_FLOW_PRIORITY = 0;

    protected ApplicationId appId;

    // Stores currently allocated slices and their traffic classes.
    protected ConsistentMap<SliceStoreKey, TrafficClassDescription> sliceStore;
    private MapEventListener<SliceStoreKey, TrafficClassDescription> sliceListener;
    private ExecutorService sliceExecutor;

    // Stores classifier flows.
    protected ConsistentMap<TrafficSelector, SliceStoreKey> classifierFlowStore;
    private MapEventListener<TrafficSelector, SliceStoreKey> classifierFlowListener;
    private ExecutorService classifierFlowExecutor;

    // Stores the default traffic class for each slice.
    protected ConsistentMap<SliceId, TrafficClass> defaultTcStore;
    private MapEventListener<SliceId, TrafficClass> defaultTcListener;
    private ExecutorService defaultTcExecutor;

    private DeviceListener deviceListener;
    private ExecutorService deviceExecutor;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);

        KryoNamespace.Builder serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(SliceId.class)
                .register(TrafficClass.class)
                .register(TrafficClassDescription.class)
                .register(QueueId.class)
                .register(SliceStoreKey.class);

        sliceStore = storageService.<SliceStoreKey, TrafficClassDescription>consistentMapBuilder()
                .withName("fabric-tna-slice")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        sliceListener = new InternalSliceListener();
        sliceExecutor = Executors.newSingleThreadExecutor(groupedThreads(
                "fabric-tna-slice-event", "%d", log));
        sliceStore.addListener(sliceListener);

        classifierFlowStore = storageService.<TrafficSelector, SliceStoreKey>consistentMapBuilder()
                .withName("fabric-tna-classifier-flow")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        classifierFlowListener = new InternalClassifierFlowListener();
        classifierFlowExecutor = Executors.newSingleThreadExecutor(groupedThreads(
                "fabric-tna-classifier-flow-event", "%d", log));
        classifierFlowStore.addListener(classifierFlowListener);

        defaultTcStore = storageService.<SliceId, TrafficClass>consistentMapBuilder()
                .withName("fabric-tna-default-tc")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        defaultTcListener = new InternalDefaultTcListener();
        defaultTcExecutor = Executors.newSingleThreadExecutor(groupedThreads(
                "fabric-tna-default-tc-event", "%d", log));
        defaultTcStore.addListener(defaultTcListener);

        // Default slice is pre-provisioned.
        sliceStore.put(new SliceStoreKey(SliceId.DEFAULT, TrafficClass.BEST_EFFORT),
                TrafficClassDescription.BEST_EFFORT);
        defaultTcStore.put(SliceId.DEFAULT, TrafficClass.BEST_EFFORT);

        deviceListener = new InternalDeviceListener();
        deviceExecutor = Executors.newSingleThreadExecutor(groupedThreads(
                "fabric-tna-device-event", "%d", log));
        deviceService.addListener(deviceListener);

        codecService.registerCodec(SliceId.class, new SliceIdCodec());
        codecService.registerCodec(TrafficClass.class, new TrafficClassCodec());

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        sliceStore.removeListener(sliceListener);
        sliceStore.destroy();
        sliceExecutor.shutdown();

        deviceService.removeListener(deviceListener);
        deviceExecutor.shutdown();

        defaultTcStore.removeListener(defaultTcListener);
        defaultTcStore.destroy();
        defaultTcExecutor.shutdown();

        // FIXME: clean up classifier flow rules and store

        codecService.unregisterCodec(SliceId.class);
        codecService.unregisterCodec(TrafficClass.class);

        log.info("Stopped");
    }

    @Override
    public boolean addSlice(SliceId sliceId) {
        if (sliceId.equals(SliceId.DEFAULT)) {
            throw new SlicingException(INVALID, "Adding the default slice is not allowed");
        }

        if (sliceExists(sliceId)) {
            throw new SlicingException(FAILED, format("Slice %s already exists", sliceId));
        }

        return addTrafficClassInternal(true, sliceId, TrafficClassDescription.BEST_EFFORT) &&
                setDefaultTrafficClass(sliceId, TrafficClass.BEST_EFFORT);
    }

    @Override
    public boolean removeSlice(SliceId sliceId) {
        if (sliceId.equals(SliceId.DEFAULT)) {
            throw new SlicingException(INVALID, "Removing the default slice is not allowed");
        }

        Set<TrafficClass> tcs = getTrafficClasses(sliceId);

        if (tcs.isEmpty() && !defaultTcStore.containsKey(sliceId)) {
            throw new SlicingException(FAILED, format("Cannot remove non-existent slice %s", sliceId));
        }

        Set<TrafficSelector> classifierFlows = getClassifierFlows(sliceId);
        if (!classifierFlows.isEmpty()) {
            throw new SlicingException(FAILED,
                    format("Cannot remove slice %s with %d classifier flow rules",
                            sliceId, classifierFlows.size()));
        }

        // Remove the default TC before removing the actual traffic classes.
        defaultTcStore.remove(sliceId);

        tcs.forEach(tc -> removeTrafficClassInternal(true, sliceId, tc));

        return true;
    }

    private boolean sliceExists(SliceId sliceId) {
        return !getTrafficClasses(sliceId).isEmpty();
    }

    @Override
    public Set<SliceId> getSlices() {
        return sliceStore.keySet().stream()
                .map(SliceStoreKey::sliceId)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean addTrafficClass(SliceId sliceId, TrafficClassDescription tcConfig) {
        return addTrafficClassInternal(false, sliceId, tcConfig);
    }

    private boolean addTrafficClassInternal(boolean addSlice, SliceId sliceId, TrafficClassDescription tcConfig) {
        if (!addSlice && !sliceExists(sliceId)) {
            throw new SlicingException(INVALID, format(
                    "Cannot add traffic class to non-existent slice %s", sliceId));
        }

        StringBuilder errorMessage = new StringBuilder();
        SliceStoreKey key = new SliceStoreKey(sliceId, tcConfig.trafficClass());
        sliceStore.compute(key, (k, v) -> {
            if (v != null) {
                errorMessage.append(format("TC %s is already allocated for slice %s",
                        tcConfig.trafficClass(), sliceId));
                return v;
            }

            log.info("Added traffic class {} to slice {}: {}", tcConfig.trafficClass(), sliceId, tcConfig);
            return tcConfig;
        });

        if (errorMessage.length() != 0) {
            // FIXME: SlicingProviderException should be checked
            throw new SlicingException(FAILED, errorMessage.toString());
        }

        return true;
    }

    @Override
    public boolean removeTrafficClass(SliceId sliceId, TrafficClass tc) {
        return removeTrafficClassInternal(false, sliceId, tc);
    }

    private boolean removeTrafficClassInternal(boolean removeSlice, SliceId sliceId, TrafficClass tc) {
        if (!sliceExists(sliceId)) {
            throw new SlicingException(INVALID, format(
                    "Cannot remove a traffic class from non-existent slice %s", sliceId));
        }

        if (!removeSlice && tc == TrafficClass.BEST_EFFORT) {
            throw new SlicingException(INVALID,
                    "Cannot remove BEST_EFFORT traffic class from any slice");
        }

        Set<TrafficSelector> classifierFlows = getClassifierFlows(sliceId, tc);
        if (!classifierFlows.isEmpty()) {
            throw new SlicingException(FAILED,
                    format("Cannot remove %s from slice %s with %d classifier flow rules",
                            tc, sliceId, classifierFlows.size()));
        }

        StringBuilder errorMessage = new StringBuilder();
        SliceStoreKey key = new SliceStoreKey(sliceId, tc);
        sliceStore.compute(key, (k, v) -> {
            if (v == null) {
                errorMessage.append(format(
                        "Traffic class %s has not been allocated for slice %s",
                        tc, sliceId));
                return null;
            }
            // Ensure the TC is not being used as Default TC
            if (tc == getDefaultTrafficClass(sliceId)) {
                errorMessage.append(format(
                        "Cannot remove %s from slice %s while it is being used " +
                                "as the default traffic class",
                        tc, sliceId));
                return v;
            }

            log.info("Removed traffic class {} from slice {}", tc, sliceId);
            return null;
        });

        if (errorMessage.length() != 0) {
            throw new SlicingException(FAILED, errorMessage.toString());
        }

        return true;
    }

    @Override
    public Set<TrafficClass> getTrafficClasses(SliceId sliceId) {
        return sliceStore.keySet().stream()
                .filter(k -> k.sliceId().equals(sliceId))
                .map(SliceStoreKey::trafficClass)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean setDefaultTrafficClass(SliceId sliceId, TrafficClass tc) {
        defaultTcStore.put(sliceId, tc);

        boolean exists = sliceStore.containsKey(new SliceStoreKey(sliceId, tc));
        if (!exists) {
            log.warn("Default traffic class {} has not been allocated yet to slice {}, " +
                            "devices might forward packets as BEST_EFFORT until the " +
                            "traffic class is allocated",
                    tc, sliceId);
        }

        return true;
    }

    @Override
    public TrafficClass getDefaultTrafficClass(SliceId sliceId) {
        return Versioned.valueOrNull(defaultTcStore.get(sliceId));
    }

    @Override
    public Map<SliceStoreKey, TrafficClassDescription> getSliceStore() {
        return Map.copyOf(sliceStore.asJavaMap());
    }

    @Override
    public boolean addClassifierFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
        if (selector.equals(DefaultTrafficSelector.emptySelector())) {
            throw new SlicingException(INVALID, "Empty traffic selector is not allowed");
        }
        // Accept 5-tuple only
        if (!fiveTupleOnly(selector)) {
            throw new SlicingException(UNSUPPORTED,
                    "Selector can only express a match on the L3-L4 5-tuple fields");
        }

        SliceStoreKey value = new SliceStoreKey(sliceId, tc);
        classifierFlowStore.compute(selector, (k, v) -> {
            log.info("classifier flow {} to slice {} tc {}", selector, sliceId, tc);
            return value;
        });

        return true;
    }

    @Override
    public boolean removeClassifierFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
        StringBuilder errorMessage = new StringBuilder();
        classifierFlowStore.compute(selector, (k, v) -> {
            if (v == null) {
                errorMessage.append(
                        format("There is no such Flow Classifier Rule %s for slice %s and TC %s",
                                selector, sliceId, tc));
                return null;
            }
            log.info("Removing flow {} from slice {} tc {}", selector, sliceId, tc);
            return null;
        });

        if (errorMessage.length() != 0) {
            throw new SlicingException(FAILED, errorMessage.toString());
        }

        return true;
    }

    @Override
    public Set<TrafficSelector> getClassifierFlows(SliceId sliceId, TrafficClass tc) {
        SliceStoreKey value = new SliceStoreKey(sliceId, tc);

        return classifierFlowStore.entrySet().stream()
                .filter(e -> e.getValue().value().equals(value))
                .map(Entry::getKey)
                .collect(Collectors.toSet());
    }

    private Set<TrafficSelector> getClassifierFlows(SliceId sliceId) {
        return classifierFlowStore.entrySet().stream()
                .filter(e -> e.getValue().value().sliceId().equals(sliceId))
                .map(Entry::getKey)
                .collect(Collectors.toSet());
    }

    private FlowRule buildDefaultTcFlowRule(DeviceId deviceId, SliceId sliceId, TrafficClass tc) {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchTernary(P4InfoConstants.HDR_SLICE_TC, sliceTcConcat(sliceId.id(), 0x00), 0x3C)
                .matchExact(P4InfoConstants.HDR_TC_UNKNOWN, 1);

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_DEFAULT_TC)
                .withParameter(new PiActionParam(P4InfoConstants.TC, tc.toInt()));

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(FABRIC_INGRESS_QOS_DEFAULT_TC)
                .fromApp(appId)
                // We suppose to get one per every SLICE, thus no need to differentiate priority
                .withPriority(DEFAULT_TC_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        log.debug("buildDefaultTcFlowRule: {}", flowRule);
        return flowRule;
    }

    private void setDefaultTrafficClass(DeviceId deviceId, SliceId sliceId, TrafficClass tc) {
        flowRuleService.applyFlowRules(buildDefaultTcFlowRule(deviceId, sliceId, tc));
        log.info("Set default TC on {} for slice {} with tc {}", deviceId, sliceId, tc);
    }

    private void resetDefaultTrafficClass(DeviceId deviceId, SliceId sliceId, TrafficClass tc) {
        flowRuleService.removeFlowRules(buildDefaultTcFlowRule(deviceId, sliceId, tc));
        log.info("Remove default TC on {} for slice {}", deviceId, sliceId);
    }

    private void addQueuesFlowRules(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        buildQueuesFlowRules(deviceId, sliceId, tc, queueId).forEach(f -> flowRuleService.applyFlowRules(f));
        log.info("Add queue table flow on {} for slice {} tc {} queueId {}", deviceId, sliceId, tc, queueId);
    }

    private void removeQueuesFlowRules(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        buildQueuesFlowRules(deviceId, sliceId, tc, queueId).forEach(f -> flowRuleService.removeFlowRules(f));
        log.info("Remove queue table flow on {} for slice {} tc {} queueId {}", deviceId, sliceId, tc, queueId);
    }

    private FabricCapabilities getCapabilities(DeviceId deviceId) throws RuntimeException {
        return pipeconfService.getPipeconf(deviceId)
                .map(FabricCapabilities::new)
                .orElseThrow(() -> new RuntimeException(
                        "Cannot get capabilities for deviceId " + deviceId.toString()));
    }

    private List<FlowRule> buildQueuesFlowRules(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        List<FlowRule> flowRules = Lists.newArrayList();
        if (tc == TrafficClass.CONTROL) {
            int red = getCapabilities(deviceId).getMeterColor(MeterColor.RED);
            int green = getCapabilities(deviceId).getMeterColor(MeterColor.GREEN);
            flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, queueId, green));
            flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, QueueId.BEST_EFFORT, red));
        } else {
            flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, queueId, null));
        }
        return flowRules;
    }

    private FlowRule buildQueuesFlowRule(DeviceId deviceId,
                                         SliceId sliceId,
                                         TrafficClass tc,
                                         QueueId queueId,
                                         Integer color) {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC, sliceTcConcat(sliceId.id(), tc.toInt()));
        if (color != null) {
            piCriterionBuilder.matchTernary(HDR_COLOR, color, 1 << HDR_COLOR_BITWIDTH - 1);
        }

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(P4InfoConstants.QID, queueId.id()));

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(appId)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        log.debug("buildFlowRule: {}", flowRule);
        return flowRule;
    }

    private void addClassifierFlowRule(DeviceId deviceId,
        TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
        FlowRule rule = buildClassifierFlowRule(deviceId, selector, sliceId, tc);
        flowRuleService.applyFlowRules(rule);
        log.info("Add classifier table flow on {} for selector {}", deviceId, selector);
    }

    private void removeClassifierFlowRule(DeviceId deviceId,
        TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
        FlowRule rule = buildClassifierFlowRule(deviceId, selector, sliceId, tc);
        flowRuleService.removeFlowRules(rule);
        log.info("Remove classifier table flow on {} for selector {}", deviceId, selector);
    }

    private FlowRule buildClassifierFlowRule(DeviceId deviceId,
        TrafficSelector selector, SliceId sliceId, TrafficClass tc) {

        PiAction.Builder piTableActionBuilder = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_SLICE_TC_CLASSIFIER_SET_SLICE_ID_TC)
                .withParameters(Set.of(new PiActionParam(P4InfoConstants.SLICE_ID, sliceId.id()),
                                       new PiActionParam(P4InfoConstants.TC, tc.toInt())));

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(P4InfoConstants.FABRIC_INGRESS_SLICE_TC_CLASSIFIER_CLASSIFIER)
                .fromApp(appId)
                .withPriority(CLASSIFIER_FLOW_PRIORITY)
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        log.debug("buildClassifierFlowRule: {}", flowRule);
        return flowRule;
    }

    private class InternalSliceListener implements MapEventListener<SliceStoreKey, TrafficClassDescription> {
        public void event(MapEvent<SliceStoreKey, TrafficClassDescription> event) {
            // Update queues table on all devices.
            // Distribute work based on QueueId.
            log.info("Processing slice event {}", event);
            sliceExecutor.submit(() -> {
                switch (event.type()) {
                    case INSERT:
                    case UPDATE:
                        if (workPartitionService.isMine(event.newValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device ->
                                    addQueuesFlowRules(device.id(), event.key().sliceId(),
                                            event.key().trafficClass(), event.newValue().value().queueId())
                            );
                        }
                        break;
                    case REMOVE:
                        if (workPartitionService.isMine(event.oldValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device ->
                                    removeQueuesFlowRules(device.id(), event.key().sliceId(),
                                            event.key().trafficClass(), event.oldValue().value().queueId())
                            );
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }

    private class InternalClassifierFlowListener implements MapEventListener<TrafficSelector, SliceStoreKey> {
        public void event(MapEvent<TrafficSelector, SliceStoreKey> event) {
            // Update classifier table on devices.
            log.info("Processing flow classifier event {}", event);
            classifierFlowExecutor.submit(() -> {
                switch (event.type()) {
                    case INSERT:
                    case UPDATE:
                        if (workPartitionService.isMine(event.newValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device -> {
                                // Classify traffic only at the edge. We use DSCP for intermediate hops.
                                if (isLeafSwitch(device.id())) {
                                    addClassifierFlowRule(device.id(), event.key(),
                                        event.newValue().value().sliceId(), event.newValue().value().trafficClass());
                                }
                            });
                        }
                        break;
                    case REMOVE:
                        if (workPartitionService.isMine(event.oldValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device -> {
                                if (isLeafSwitch(device.id())) {
                                    removeClassifierFlowRule(device.id(), event.key(),
                                        event.oldValue().value().sliceId(), event.oldValue().value().trafficClass());
                                }
                            });
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }

    private class InternalDefaultTcListener implements  MapEventListener<SliceId, TrafficClass> {
        @Override
        public void event(MapEvent<SliceId, TrafficClass> event) {
            // Update default tc tables.
            log.info("Processing Default TC event {}", event);
            defaultTcExecutor.submit(() -> {
                switch (event.type()) {
                    case INSERT:
                    case UPDATE:
                        if (workPartitionService.isMine(event.newValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device -> {
                                if (isLeafSwitch(device.id())) {
                                    setDefaultTrafficClass(device.id(), event.key(),
                                                          event.newValue().value());
                                }
                            });
                        }
                        break;
                    case REMOVE:
                        if (workPartitionService.isMine(event.oldValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device -> {
                                if (isLeafSwitch(device.id())) {
                                    resetDefaultTrafficClass(device.id(), event.key(),
                                                           event.oldValue().value());
                                }
                            });
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            // Provision all tables on device.
            log.info("Processing device event {}", event);
            deviceExecutor.submit(() -> {
                switch (event.type()) {
                    case DEVICE_ADDED:
                    case DEVICE_AVAILABILITY_CHANGED:
                        DeviceId deviceId = event.subject().id();
                        if (workPartitionService.isMine(deviceId, toStringHasher())) {
                            if (deviceService.isAvailable(deviceId)) {
                                sliceStore.forEach(e -> addQueuesFlowRules(deviceId,
                                        e.getKey().sliceId(), e.getKey().trafficClass(), e.getValue().value().queueId())
                                );
                                if (isLeafSwitch(deviceId)) {
                                    classifierFlowStore.forEach(e -> addClassifierFlowRule(deviceId,
                                        e.getKey(), e.getValue().value().sliceId(), e.getValue().value().trafficClass())
                                    );
                                    defaultTcStore.forEach(e -> setDefaultTrafficClass(
                                            deviceId, e.getKey(), e.getValue().value()));
                                }
                            }
                        }
                        break;
                    default:
                        break;
                }
            });
        }

        @Override
        public boolean isRelevant(DeviceEvent event) {
            return event.type() == DeviceEvent.Type.DEVICE_ADDED ||
                    event.type() == DeviceEvent.Type.DEVICE_AVAILABILITY_CHANGED;
        }
    }

    private static <K> Function<K, Long> toStringHasher() {
        return k -> Hashing.sha256().hashUnencodedChars(k.toString()).asLong();
    }

    private boolean isLeafSwitch(DeviceId deviceId) {
        SegmentRoutingDeviceConfig cfg = networkCfgService.getConfig(deviceId, SegmentRoutingDeviceConfig.class);
        return cfg != null && cfg.isEdgeRouter();
    }
}
