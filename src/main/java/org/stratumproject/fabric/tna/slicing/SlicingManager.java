// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;
import org.apache.commons.lang.NotImplementedException;
import org.onlab.util.KryoNamespace;
import org.onosproject.codec.CodecService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.intent.WorkPartitionService;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.slicing.SliceId;
import org.onosproject.net.slicing.SlicingService;
import org.onosproject.net.slicing.TrafficClass;
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
import org.stratumproject.fabric.tna.slicing.api.SlicingAdminService;
import org.stratumproject.fabric.tna.web.SliceIdCodec;
import org.stratumproject.fabric.tna.web.TrafficClassCodec;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.behaviour.Constants.DEFAULT_SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.Constants.MAX_SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.tcToFabricConstants;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_QUEUES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR_BITWIDTH;

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

    private static final Logger log = getLogger(SlicingManager.class);
    private static final String APP_NAME = "org.stratumproject.fabric.tna.slicing"; // TODO revisit naming
    private static final int QOS_FLOW_PRIORITY = 10;

    protected ApplicationId appId;

    protected ConsistentMap<SliceStoreKey, QueueId> sliceStore;
    private MapEventListener<SliceStoreKey, QueueId> sliceListener;
    private ExecutorService sliceExecutor;

    protected ConsistentMap<QueueId, QueueStoreValue> queueStore;
    private MapEventListener<QueueId, QueueStoreValue> queueListener;
    private ExecutorService queueExecutor;

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
        sliceStore.put(new SliceStoreKey(SliceId.of(DEFAULT_SLICE_ID), TrafficClass.BEST_EFFORT), QueueId.BEST_EFFORT);

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
        queueStore.put(QueueId.of(3), new QueueStoreValue(TrafficClass.REAL_TIME, true));
        queueStore.put(QueueId.of(6), new QueueStoreValue(TrafficClass.ELASTIC, true));

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
        checkArgument(sliceId.id() != DEFAULT_SLICE_ID, "Adding default slice is not allowed");
        checkArgument(sliceId.id() <= MAX_SLICE_ID, "Invalid slice id");

        return addTrafficClass(sliceId, TrafficClass.BEST_EFFORT);
    }

    @Override
    public boolean removeSlice(SliceId sliceId) {
        checkArgument(sliceId.id() != DEFAULT_SLICE_ID, "Removing default slice is not allowed");
        checkArgument(sliceId.id() <= MAX_SLICE_ID, "Invalid slice id");

        Set<TrafficClass> tcs = getTrafficClasses(sliceId);
        if (tcs.isEmpty()) {
            log.warn("Cannot remove a non-existent slice {}", sliceId);
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
        checkArgument(tc != TrafficClass.SYSTEM, "SYSTEM TC should not be associated with any slice");

        // Ensure the presence of BEST_EFFORT TC in the slice
        if (tc != TrafficClass.BEST_EFFORT) {
            SliceStoreKey beKey = new SliceStoreKey(sliceId, TrafficClass.BEST_EFFORT);
            if (!sliceStore.containsKey(beKey)) {
                log.warn("Slice {} doesn't exist yet", sliceId);
                return false;
            }
        }

        AtomicBoolean result = new AtomicBoolean(false);

        SliceStoreKey key = new SliceStoreKey(sliceId, tc);
        sliceStore.compute(key, (k, v) -> {
            if (v != null) {
               log.warn("TC {} is already allocated for slice {}", tc, sliceId);
               return v;
            }

            QueueId queueId = allocateQueue(tc);
            if (queueId == null) {
                log.warn("Unable to find available queue for {}", tc);
                return null;
            }

            log.info("Allocate queue {} for slice {} tc {}", queueId, sliceId, tc);
            result.set(true);
            return queueId;
        });

        return result.get();
    }

    @Override
    public boolean removeTrafficClass(SliceId sliceId, TrafficClass tc) {
        // Ensure the presence of BEST_EFFORT TC in the slice
        if (tc == TrafficClass.BEST_EFFORT) {
            checkArgument(sliceId.id() != DEFAULT_SLICE_ID,
                String.format("Removing %s from default slice is not allowed", tc));

            checkArgument(!getTrafficClasses(sliceId).stream().anyMatch(existTc -> existTc != TrafficClass.BEST_EFFORT),
                String.format("Can't remove %s from slice: %s while another TC exists", tc, sliceId));
        }

        AtomicBoolean result = new AtomicBoolean(false);

        SliceStoreKey key = new SliceStoreKey(sliceId, tc);
        sliceStore.compute(key, (k, v) -> {
            if (v == null) {
                log.warn("TC {} has not been allocated to slice {}", tc, sliceId);
                return null;
            }

            deallocateQueue(v);
            log.info("Deallocate queue {} for slice {} tc {}", v, sliceId, tc);
            result.set(true);
            return null;
        });

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
    public boolean addFlow(TrafficTreatment treatment, SliceId sliceId, TrafficClass tc) {
        throw new NotImplementedException("addFlow is not implemented in Slicing Manager");
    }

    @Override
    public boolean removeFlow(TrafficTreatment treatment, SliceId sliceId, TrafficClass tc) {
        throw new NotImplementedException("removeFlow is not implemented in Slicing Manager");
    }

    @Override
    public Set<TrafficTreatment> getFlows(SliceId sliceId, TrafficClass tc) {
        throw new NotImplementedException("getFlows is not implemented in Slicing Manager");
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
                .matchExact(P4InfoConstants.HDR_SLICE_TC, sliceTcConcat(sliceId.id(), tcToFabricConstants(tc)));
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
}
