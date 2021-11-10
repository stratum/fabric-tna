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
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;
import org.stratumproject.fabric.tna.slicing.api.Color;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingAdminService;
import org.stratumproject.fabric.tna.slicing.api.SlicingException;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;
import org.stratumproject.fabric.tna.web.SliceIdCodec;
import org.stratumproject.fabric.tna.web.TrafficClassCodec;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.fiveTupleOnly;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_QUEUES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR_BITWIDTH;
import static org.stratumproject.fabric.tna.slicing.api.SlicingException.ErrorType.FAILED;
import static org.stratumproject.fabric.tna.slicing.api.SlicingException.ErrorType.INVALID;
import static org.stratumproject.fabric.tna.slicing.api.SlicingException.ErrorType.UNSUPPORTED;

/**
 * Implementation of SlicingService.
 */
@Component(immediate = true, service = {
        SlicingService.class,
        SlicingAdminService.class
})
public class SlicingManager implements SlicingService, SlicingAdminService {
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

    private static final Logger log = getLogger(SlicingManager.class);
    private static final String APP_NAME = "org.stratumproject.fabric.tna.slicing"; // TODO revisit naming
    private static final int QOS_FLOW_PRIORITY = 10;

    // We use the lowest priority to avoid overriding the port-based trust_dscp rules installed
    // when translating filtering objectives.
    private static final int CLASSIFIER_FLOW_PRIORITY = 0;

    protected ApplicationId appId;

    protected ConsistentMap<SliceStoreKey, QueueId> sliceStore;
    private MapEventListener<SliceStoreKey, QueueId> sliceListener;
    private ExecutorService sliceExecutor;

    protected ConsistentMap<QueueId, QueueStoreValue> queueStore;
    private MapEventListener<QueueId, QueueStoreValue> queueListener;
    private ExecutorService queueExecutor;

    protected ConsistentMap<TrafficSelector, SliceStoreKey> classifierFlowStore;
    private MapEventListener<TrafficSelector, SliceStoreKey> classifierFlowListener;
    private ExecutorService classifierFlowExecutor;

    private DeviceListener deviceListener;
    private ExecutorService deviceExecutor;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);

        KryoNamespace.Builder serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(SliceId.class)
                .register(TrafficClass.class)
                .register(QueueId.class)
                .register(SliceStoreKey.class)
                .register(QueueStoreValue.class);

        sliceStore = storageService.<SliceStoreKey, QueueId>consistentMapBuilder()
                .withName("fabric-tna-slice")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        sliceListener = new InternalSliceListener();
        sliceExecutor = Executors.newSingleThreadExecutor(groupedThreads("fabric-tna-slice-event", "%d", log));
        sliceStore.addListener(sliceListener);

        // Default slice is pre-provisioned
        sliceStore.put(new SliceStoreKey(SliceId.DEFAULT, TrafficClass.BEST_EFFORT), QueueId.BEST_EFFORT);

        queueStore = storageService.<QueueId, QueueStoreValue>consistentMapBuilder()
                .withName("fabric-tna-queue")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        queueListener = new InternalQueueListener();
        queueExecutor = Executors.newSingleThreadExecutor(groupedThreads("fabric-tna-queue-event", "%d", log));
        queueStore.addListener(queueListener);

        // Shared queues are pre-provisioned and always available
        queueStore.put(QueueId.BEST_EFFORT, new QueueStoreValue(TrafficClass.BEST_EFFORT, true));
        queueStore.put(QueueId.SYSTEM, new QueueStoreValue(TrafficClass.SYSTEM, true));
        queueStore.put(QueueId.CONTROL, new QueueStoreValue(TrafficClass.CONTROL, true));

        // FIXME Dedicate queues should be dynamically provisioned via API in the future
        // This configuration is based on the util/sample-qos-config.yaml queues configuration
        // Max rate = 45 Mbps
        queueStore.put(QueueId.of(3), new QueueStoreValue(TrafficClass.REAL_TIME, true));
        // Max rate = 30 Mbps
        queueStore.put(QueueId.of(4), new QueueStoreValue(TrafficClass.REAL_TIME, true));
        // Max rate = 25 Mbps
        queueStore.put(QueueId.of(5), new QueueStoreValue(TrafficClass.REAL_TIME, true));
        // Min guaranteed rate = 100 Mbps
        queueStore.put(QueueId.of(6), new QueueStoreValue(TrafficClass.ELASTIC, true));
        // Min guaranteed rate = 200 Mbps
        queueStore.put(QueueId.of(7), new QueueStoreValue(TrafficClass.ELASTIC, true));

        classifierFlowStore = storageService.<TrafficSelector, SliceStoreKey>consistentMapBuilder()
                .withName("fabric-tna-classifier-flow")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        classifierFlowListener = new InternalFlowListener();
        classifierFlowExecutor = Executors.newSingleThreadExecutor(groupedThreads("fabric-tna-flow-event", "%d", log));
        classifierFlowStore.addListener(classifierFlowListener);

        deviceListener = new InternalDeviceListener();
        deviceExecutor = Executors.newSingleThreadExecutor(groupedThreads("fabric-tna-device-event", "%d", log));
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

        queueStore.removeListener(queueListener);
        queueStore.destroy();
        queueExecutor.shutdown();

        deviceService.removeListener(deviceListener);
        deviceExecutor.shutdown();

        codecService.unregisterCodec(SliceId.class);
        codecService.unregisterCodec(TrafficClass.class);

        log.info("Stopped");
    }

    @Override
    public boolean addSlice(SliceId sliceId) {
        if (sliceId.equals(SliceId.DEFAULT)) {
            throw new SlicingException(INVALID, "Adding default slice is not allowed");
        }

        return addTrafficClass(sliceId, TrafficClass.BEST_EFFORT);
    }

    @Override
    public boolean removeSlice(SliceId sliceId) {
        if (sliceId.equals(SliceId.DEFAULT)) {
            throw new SlicingException(INVALID, "Removing default slice is not allowed");
        }

        Set<TrafficClass> tcs = getTrafficClasses(sliceId);
        if (tcs.isEmpty()) {
            throw new SlicingException(FAILED, String.format("Cannot remove a non-existent slice %s", sliceId));
        }

        Set<TrafficSelector> classifierFlows = getFlows(sliceId);
        if (!classifierFlows.isEmpty()) {
            log.warn("Cannot remove slice {} with {} Flow Classifier Rules",
                     sliceId, classifierFlows.size());
            return false;
        }

        AtomicBoolean result = new AtomicBoolean(true);

        tcs.stream()
                .sorted(Comparator.comparingInt(TrafficClass::ordinal).reversed()) // Remove BEST_EFFORT the last
                .forEach(tc -> {
            if (!removeTrafficClass(sliceId, tc)) {
                result.set(false);
            }
        });

        return result.get();
    }

    @Override
    public Set<SliceId> getSlices() {
        return sliceStore.keySet().stream()
                .map(SliceStoreKey::sliceId)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean addTrafficClass(SliceId sliceId, TrafficClass tc) {
        if (tc == TrafficClass.SYSTEM) {
            throw new SlicingException(INVALID, "SYSTEM TC should not be associated with any slice");
        }

        // Ensure the presence of BEST_EFFORT TC in the slice
        if (tc != TrafficClass.BEST_EFFORT) {
            SliceStoreKey beKey = new SliceStoreKey(sliceId, TrafficClass.BEST_EFFORT);
            if (!sliceStore.containsKey(beKey)) {
                throw new SlicingException(FAILED, String.format("Slice %s doesn't exist yet", sliceId));
            }
        }

        AtomicBoolean result = new AtomicBoolean(false);

        StringBuilder errorMessage = new StringBuilder();
        SliceStoreKey key = new SliceStoreKey(sliceId, tc);
        sliceStore.compute(key, (k, v) -> {
            if (v != null) {
                errorMessage.append(String.format("TC %s is already allocated for slice %s", tc, sliceId));
                return v;
            }

            QueueId queueId = allocateQueue(tc);
            if (queueId == null) {
                errorMessage.append(String.format("Unable to find available queue for %s", tc));
                return null;
            }

            log.info("Allocate queue {} for slice {} tc {}", queueId, sliceId, tc);
            result.set(true);
            return queueId;
        });

        if (errorMessage.length() != 0) {
            throw new SlicingException(FAILED, errorMessage.toString());
        }

        return result.get();
    }

    @Override
    public boolean removeTrafficClass(SliceId sliceId, TrafficClass tc) {
        // Ensure the presence of BEST_EFFORT TC in the slice
        if (tc == TrafficClass.BEST_EFFORT) {
            if (sliceId.equals(SliceId.DEFAULT)) {
                throw new SlicingException(INVALID,
                    String.format("Removing %s from slice %s is not allowed", tc, sliceId));
            }
            if (getTrafficClasses(sliceId).stream().anyMatch(existTc -> existTc != TrafficClass.BEST_EFFORT)) {
                throw new SlicingException(UNSUPPORTED,
                    String.format("Can't remove %s from slice %s while another TC exists", tc, sliceId));
            }
        }

        Set<TrafficSelector> classifierFlows = getFlows(sliceId, tc);
        if (!classifierFlows.isEmpty()) {
            log.warn("Cannot remove {} from slice {} with {} Flow Classifier Rules",
                     tc, sliceId, classifierFlows.size());
            return false;
        }

        AtomicBoolean result = new AtomicBoolean(false);

        StringBuilder errorMessage = new StringBuilder();
        SliceStoreKey key = new SliceStoreKey(sliceId, tc);
        sliceStore.compute(key, (k, v) -> {
            if (v == null) {
                errorMessage.append(String.format("TC %s has not been allocated to slice %s", tc, sliceId));
                return null;
            }

            deallocateQueue(v);
            log.info("Deallocate queue {} for slice {} tc {}", v, sliceId, tc);
            result.set(true);
            return null;
        });

        if (errorMessage.length() != 0) {
            throw new SlicingException(FAILED, errorMessage.toString());
        }

        return result.get();
    }

    @Override
    public Set<TrafficClass> getTrafficClasses(SliceId sliceId) {
        return sliceStore.keySet().stream()
                .filter(k -> k.sliceId().equals(sliceId))
                .map(SliceStoreKey::trafficClass)
                .collect(Collectors.toSet());
    }

    @Override
    public Map<SliceStoreKey, QueueId> getSliceStore() {
        return Map.copyOf(sliceStore.asJavaMap());
    }

    @Override
    public boolean addFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
        if (selector.equals(DefaultTrafficSelector.emptySelector())) {
            log.warn("Empty traffic selector is not allowed");
            return false;
        }
        // Accept 5-tuple only
        if (!fiveTupleOnly(selector)) {
            log.warn("Only accept 5-tuple {}", selector);
            return false;
        }

        SliceStoreKey value = new SliceStoreKey(sliceId, tc);
        classifierFlowStore.compute(selector, (k, v) -> {
            log.info("classifier flow {} to slice {} tc {}", selector, sliceId, tc);
            return value;
        });

        return true;
    }

    @Override
    public boolean removeFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
        AtomicBoolean result = new AtomicBoolean(false);
        classifierFlowStore.compute(selector, (k, v) -> {
            if (v == null) {
                log.warn("There is no such Flow Classifier Rule {} for slice {}  and TC {}", selector, sliceId, tc);
                return null;
            }
            log.info("Removing flow {} from slice {} tc {}", selector, sliceId, tc);
            result.set(true);
            return null;
        });
        return result.get();
    }

    @Override
    public Set<TrafficSelector> getFlows(SliceId sliceId, TrafficClass tc) {
        SliceStoreKey value = new SliceStoreKey(sliceId, tc);

        return classifierFlowStore.entrySet().stream()
                .filter(e -> e.getValue().value().equals(value))
                .map(Entry::getKey)
                .collect(Collectors.toSet());
    }

    private Set<TrafficSelector> getFlows(SliceId sliceId) {
        return classifierFlowStore.entrySet().stream()
                .filter(e -> e.getValue().value().sliceId().equals(sliceId))
                .map(Entry::getKey)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean reserveQueue(QueueId queueId, TrafficClass tc) {
        AtomicBoolean result = new AtomicBoolean(false);

        queueStore.compute(queueId, (k, v) -> {
            if (v != null) {
                log.warn("Queue {} has already been allocated to TC {}", k, v);
                return v;
            }
            log.info("Queue {} successfully reserved for TC {}", k, tc);
            result.set(true);
            return new QueueStoreValue(tc, true);
        });

        return result.get();
    }

    @Override
    public boolean releaseQueue(QueueId queueId) {
        AtomicBoolean result = new AtomicBoolean(false);

        queueStore.compute(queueId, (k, v) -> {
            if (v == null) {
               log.warn("Queue {} is not reserved", queueId);
               return null;
            }
            if (!v.available()) {
               log.warn("Queue {} in use", queueId);
               return v;
            }
            log.info("Queue {} is released from TC {}", queueId, v.trafficClass());
            result.set(true);
            return null;
        });

        return result.get();
    }

    @Override
    public Map<QueueId, QueueStoreValue> getQueueStore() {
        return Map.copyOf(queueStore.asJavaMap());
    }

    private QueueId allocateQueue(TrafficClass tc) {
        Optional<QueueId> queueId = queueStore.stream()
                .filter(e -> e.getValue().value().trafficClass() == tc)
                .filter(e -> e.getValue().value().available())
                .findFirst()
                .map(Map.Entry::getKey);

        if (queueId.isPresent()) {
            // Don't mark shared queues as they are always available.
            if (tc != TrafficClass.BEST_EFFORT &&
                    tc != TrafficClass.SYSTEM &&
                    tc != TrafficClass.CONTROL) {
                queueStore.compute(queueId.get(), (k, v) -> {
                    v.setAvailable(false);
                    return v;
                });
            }
            log.info("Allocated queue {} to TC {}", queueId.get(), tc);
            return queueId.get();
        } else {
            log.warn("No queue available for TC {}", tc);
            return null;
        }
    }

    private boolean deallocateQueue(QueueId queueId) {
        AtomicBoolean result = new AtomicBoolean(false);

        queueStore.compute(queueId, (k, v) -> {
           if (v == null) {
               log.warn("Queue {} not reserved yet", queueId);
               return v;
           }
           v.setAvailable(true);
           result.set(true);
           return v;
        });

        return result.get();
    }

    private void addQueueTable(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        buildFlowRules(deviceId, sliceId, tc, queueId).forEach(f -> flowRuleService.applyFlowRules(f));
        log.info("Add queue table flow on {} for slice {} tc {} queueId {}", deviceId, sliceId, tc, queueId);
    }

    private void removeQueueTable(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        buildFlowRules(deviceId, sliceId, tc, queueId).forEach(f -> flowRuleService.removeFlowRules(f));
        log.info("Remove queue table flow on {} for slice {} tc {} queueId {}", deviceId, sliceId, tc, queueId);
    }

    private List<FlowRule> buildFlowRules(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        List<FlowRule> flowRules = Lists.newArrayList();
        if (tc == TrafficClass.CONTROL) {
            flowRules.add(buildFlowRule(deviceId, sliceId, tc, queueId, Color.GREEN));
            flowRules.add(buildFlowRule(deviceId, sliceId, tc, QueueId.BEST_EFFORT, Color.RED));
        } else {
            flowRules.add(buildFlowRule(deviceId, sliceId, tc, queueId, null));
        }
        return flowRules;
    }

    private FlowRule buildFlowRule(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId, Color color) {
        PiCriterion.Builder piCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_SLICE_TC, sliceTcConcat(sliceId.id(), tc.ordinal()));
        if (color != null) {
            piCriterionBuilder.matchTernary(HDR_COLOR, color.ordinal(), 1 << HDR_COLOR_BITWIDTH - 1);
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

        log.info("{}", flowRule);
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
                                       new PiActionParam(P4InfoConstants.TC, tc.ordinal())));

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(P4InfoConstants.FABRIC_INGRESS_SLICE_TC_CLASSIFIER_CLASSIFIER)
                .fromApp(appId)
                .withPriority(CLASSIFIER_FLOW_PRIORITY)
                .withSelector(selector)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        log.info("{}", flowRule);
        return flowRule;
    }

    private class InternalSliceListener implements MapEventListener<SliceStoreKey, QueueId> {
        public void event(MapEvent<SliceStoreKey, QueueId> event) {
            // Distributed work based on QueueId. Consistent with InternalQueueListener
            log.info("Processing slice event {}", event);
            sliceExecutor.submit(() -> {
                switch (event.type()) {
                    case INSERT:
                    case UPDATE:
                        if (workPartitionService.isMine(event.newValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device ->
                                addQueueTable(device.id(),
                                        event.key().sliceId(), event.key().trafficClass(), event.newValue().value())
                            );
                        }
                        break;
                    case REMOVE:
                        if (workPartitionService.isMine(event.oldValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device ->
                                removeQueueTable(device.id(),
                                        event.key().sliceId(), event.key().trafficClass(), event.oldValue().value())
                            );
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }

    private class InternalQueueListener implements MapEventListener<QueueId, QueueStoreValue> {
        public void event(MapEvent<QueueId, QueueStoreValue> event) {
            // Distributed work based on QueueId. Consistent with InternalQueueListener
            log.info("Processing queue event {}", event);
            sliceExecutor.submit(() -> {
                switch (event.type()) {
                    case INSERT:
                    case UPDATE:
                        if (workPartitionService.isMine(event.newValue().value(), toStringHasher())) {
                            // TODO programmatically config queues
                        }
                        break;
                    case REMOVE:
                        if (workPartitionService.isMine(event.oldValue().value(), toStringHasher())) {
                            // TODO programmatically config queues
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }

    private class InternalFlowListener implements MapEventListener<TrafficSelector, SliceStoreKey> {
        public void event(MapEvent<TrafficSelector, SliceStoreKey> event) {
            log.info("Processing flow classifier event {}", event);
            classifierFlowExecutor.submit(() -> {
                switch (event.type()) {
                    case INSERT:
                    case UPDATE:
                        if (workPartitionService.isMine(event.newValue().value(), toStringHasher())) {
                            deviceService.getAvailableDevices().forEach(device -> {
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

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            log.info("Processing device event {}", event);
            deviceExecutor.submit(() -> {
                switch (event.type()) {
                    case DEVICE_ADDED:
                    case DEVICE_AVAILABILITY_CHANGED:
                        DeviceId deviceId = event.subject().id();
                        if (workPartitionService.isMine(deviceId, toStringHasher())) {
                            if (deviceService.isAvailable(deviceId)) {
                                sliceStore.forEach(e -> addQueueTable(deviceId,
                                        e.getKey().sliceId(), e.getKey().trafficClass(), e.getValue().value())
                                );
                                if (isLeafSwitch(deviceId)) {
                                    classifierFlowStore.forEach(e -> addClassifierFlowRule(deviceId,
                                        e.getKey(), e.getValue().value().sliceId(), e.getValue().value().trafficClass())
                                    );
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
