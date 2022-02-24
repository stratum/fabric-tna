// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing;

import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;
import org.onlab.util.KryoNamespace;
import org.onosproject.cli.net.IpProtocol;
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
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
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
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.Constants.APP_NAME_SLICING;
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
        SlicingProviderService.class,
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
    private static final int QUEUES_FLOW_PRIORITY_LOW = 10;
    private static final int QUEUES_FLOW_PRIORITY_HIGH = 20;
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

    private final AtomicReference<SliceId> systemSliceId = new AtomicReference<>();
    private final AtomicReference<TrafficClassDescription> systemTc = new AtomicReference<>();

    private DeviceListener deviceListener;
    private ExecutorService deviceExecutor;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME_SLICING, this::preDeactivate);

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

    // Called only when we intentionally deactivate the app.
    protected void preDeactivate() {
        sliceStore.destroy();
        defaultTcStore.destroy();
    }

    @Deactivate
    protected void deactivate() {
        sliceStore.removeListener(sliceListener);
        sliceExecutor.shutdown();

        deviceService.removeListener(deviceListener);
        deviceExecutor.shutdown();

        defaultTcStore.removeListener(defaultTcListener);
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
    public boolean addTrafficClass(SliceId sliceId, TrafficClassDescription tcDescription) {
        return addTrafficClassInternal(false, sliceId, tcDescription);
    }

    private boolean addTrafficClassInternal(boolean addSlice, SliceId sliceId, TrafficClassDescription tcDescription) {
        if (!addSlice && !sliceExists(sliceId)) {
            throw new SlicingException(INVALID, format(
                    "Cannot add traffic class to non-existent slice %s", sliceId));
        }

        StringBuilder errorMessage = new StringBuilder();
        SliceStoreKey key = new SliceStoreKey(sliceId, tcDescription.trafficClass());
        sliceStore.compute(key, (k, v) -> {
            if (v != null) {
                errorMessage.append(format("TC %s is already allocated for slice %s",
                        tcDescription.trafficClass(), sliceId));
                return v;
            }

            log.info("Added traffic class {} to slice {}: {}", tcDescription.trafficClass(), sliceId, tcDescription);
            return tcDescription;
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
    public void resetDefaultTrafficClassForAllSlices() {
        for (SliceId sliceId : defaultTcStore.keySet()) {
            setDefaultTrafficClass(sliceId, TrafficClass.BEST_EFFORT);
        }
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
        try {
            validateFiveTuple(selector);
        } catch (SlicingException e) {
            throw new SlicingException(e.type(), format(
                    "Invalid selector (%s)", e.getMessage()));
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
    public void removeAllClassifierFlows() {
        classifierFlowStore.clear();
    }

    @Override
    public Set<TrafficSelector> getClassifierFlows(SliceId sliceId, TrafficClass tc) {
        SliceStoreKey value = new SliceStoreKey(sliceId, tc);

        return classifierFlowStore.entrySet().stream()
                .filter(e -> e.getValue().value().equals(value))
                .map(Entry::getKey)
                .collect(Collectors.toSet());
    }

    @Override
    public SliceId getSystemSlice() {
        var sliceId = systemSliceId.get();
        return sliceId == null ? SliceId.DEFAULT : sliceId;
    }

    @Override
    public TrafficClassDescription getSystemTrafficClass() {
        var tc = systemTc.get();
        return tc == null ? TrafficClassDescription.BEST_EFFORT : tc;
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
        int green = getCapabilities(deviceId).getMeterColor(MeterColor.GREEN);
        int red = getCapabilities(deviceId).getMeterColor(MeterColor.RED);
        switch (tc) {
            case CONTROL:
                // The control queue can be shared between multiple slices for
                // delay-critical low-loss traffic. To guarantee isolation
                // between slices, only green traffic can be admitted to the
                // queue.
                flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, queueId, green,
                        QUEUES_FLOW_PRIORITY_HIGH));
                // Given the low-loss property, we do not drop control packets
                // unless absolutely necessary. Hence, all other colors (yellow,
                // red) are redirected to best-effort.
                flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, QueueId.BEST_EFFORT, null,
                        QUEUES_FLOW_PRIORITY_LOW));
                break;
            case REAL_TIME:
            case ELASTIC:
                // Real-time and elastic queues are dedicated per slice.
                // However, to limit interference between different users within
                // the same slice (e.g., different UEs for the P4-UPF slice), we
                // only admit green and yellow traffic, while red traffic is
                // dropped.
                flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, null, red,
                        QUEUES_FLOW_PRIORITY_HIGH));
                flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, queueId, null,
                        QUEUES_FLOW_PRIORITY_LOW));
                break;
            case BEST_EFFORT:
                // The best-effort queue is shared between all slices. We do not
                // provide any QoS guarantees, all colors are admitted.
                flowRules.add(buildQueuesFlowRule(deviceId, sliceId, tc, queueId, null,
                        QUEUES_FLOW_PRIORITY_LOW));
                break;
            default:
                log.error("Unknown TC {}, cannot generate queues flow rules", tc);
        }
        return flowRules;
    }

    private FlowRule buildQueuesFlowRule(DeviceId deviceId,
                                         SliceId sliceId,
                                         TrafficClass tc,
                                         QueueId queueId,
                                         Integer color,
                                         int priority) {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC, sliceTcConcat(sliceId.id(), tc.toInt()));
        if (color != null) {
            piCriterionBuilder.matchTernary(HDR_COLOR, color, 1 << HDR_COLOR_BITWIDTH - 1);
        }

        PiAction.Builder piTableActionBuilder;
        if (queueId != null) {
            piTableActionBuilder = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE)
                    .withParameter(new PiActionParam(P4InfoConstants.QID, queueId.id()));
        } else {
            // Drop
            piTableActionBuilder = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_INGRESS_QOS_METER_DROP);
        }

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(PiTableId.of(FABRIC_INGRESS_QOS_QUEUES.id()))
                .fromApp(appId)
                .withPriority(priority)
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

    private void updateSystemTc() {
        // Use getters to resolve null to the default values.
        SliceId oldSystemSliceId = getSystemSlice();
        TrafficClassDescription oldSystemTc = getSystemTrafficClass();
        Set<SliceStoreKey> newSystemKeys = sliceStore.stream()
                .filter(e -> e.getValue().value().isSystemTc())
                .map(Entry::getKey)
                .collect(Collectors.toSet());
        if (newSystemKeys.isEmpty()) {
            systemSliceId.set(null);
            systemTc.set(null);
        } else {
            if (newSystemKeys.size() > 1) {
                log.warn("Found more than one system traffic class, will pick a random one: {}", newSystemKeys);
            }
            var key = newSystemKeys.iterator().next();
            Versioned<TrafficClassDescription> entry = sliceStore.get(key);
            if (entry == null) {
                log.error("Missing slice store entry for the system traffic class, BUG?");
                systemSliceId.set(null);
                systemTc.set(null);
            } else {
                systemSliceId.set(key.sliceId());
                systemTc.set(entry.value());
            }
        }
        if (!getSystemSlice().equals(oldSystemSliceId) ||
                !getSystemTrafficClass().equals(oldSystemTc)) {
            log.info("System slice or traffic class updated: sliceId={}, tc={}",
                    getSystemSlice(), getSystemTrafficClass());
        }
    }

    private void validateFiveTuple(TrafficSelector selector)
            throws SlicingException {
        // 5-tuple only, IP_PROTO required when matching on L4 ports.
        short protoNeeded = -1;
        short protoFound = 0;
        for (Criterion criterion : selector.criteria()) {
            Criterion.Type type = criterion.type();
            if (type == Criterion.Type.IP_PROTO) {
                protoFound = ((IPProtocolCriterion) criterion).protocol();
            } else if (type == Criterion.Type.TCP_SRC ||
                    type == Criterion.Type.TCP_DST) {
                protoNeeded = IpProtocol.TCP.value();
            } else if (type == Criterion.Type.UDP_SRC ||
                    type == Criterion.Type.UDP_DST) {
                protoNeeded = IpProtocol.UDP.value();
            } else if (!(type == Criterion.Type.IPV4_SRC ||
                    type == Criterion.Type.IPV4_DST)) {
                throw new SlicingException(UNSUPPORTED, format(
                        "matching on %s is not supported, only L3-L4 5-tuples fields are supported", type));
            }
        }

        if (protoNeeded != -1 && protoNeeded != protoFound) {
            throw new SlicingException(INVALID, format(
                    "missing or invalid %s, expected %s=%s",
                    Criterion.Type.IP_PROTO, Criterion.Type.IP_PROTO, protoNeeded));
        }

    }

    private class InternalSliceListener implements MapEventListener<SliceStoreKey, TrafficClassDescription> {
        public void event(MapEvent<SliceStoreKey, TrafficClassDescription> event) {
            // Update queues table on all devices.
            // Distribute work based on QueueId.
            log.info("Processing slice event {}", event);
            sliceExecutor.submit(() -> {
                updateSystemTc();
                switch (event.type()) {
                    case INSERT:
                    case UPDATE:
                        // FIXME: should we handle UPDATE differently? E.g., removing old queues entries?
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
