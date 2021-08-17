// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;
import org.apache.commons.lang.NotImplementedException;
import org.onlab.util.KryoNamespace;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
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
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_STATS_FLOWS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_COLOR_BITWIDTH;

/**
 * Implementation of SlicingService.
 */
@Component(immediate = true, service = SlicingService.class)
public class SlicingManager implements SlicingService {
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

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);

        KryoNamespace.Builder serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(SliceId.class)
                .register(TrafficClass.class)
                .register(QueueId.class)
                .register(SliceStoreKey.class);

        sliceStore = storageService.<SliceStoreKey, QueueId>consistentMapBuilder()
                .withName("fabric-tna-slice")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        sliceListener = new InternalSliceListener();
        sliceExecutor =  Executors.newSingleThreadExecutor(groupedThreads("fabric-tna-slice-event", "%d", log));

        queueStore = storageService.<QueueId, QueueStoreValue>consistentMapBuilder()
                .withName("fabric-tna-queue")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build();
        queueListener = new InternalQueueListener();
        queueExecutor =  Executors.newSingleThreadExecutor(groupedThreads("fabric-tna-queue-event", "%d", log));

        // Shared queues are pre-provisioned and always available
        queueStore.put(QueueId.BEST_EFFORT, new QueueStoreValue(TrafficClass.BEST_EFFORT, true));
        queueStore.put(QueueId.SYSTEM, new QueueStoreValue(TrafficClass.SYSTEM, true));
        queueStore.put(QueueId.CONTROL, new QueueStoreValue(TrafficClass.CONTROL, true));

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

        log.info("Stopped");
    }

    @Override
    public boolean addSlice(SliceId sliceId) {
        return addTrafficClass(sliceId, TrafficClass.BEST_EFFORT);
    }

    @Override
    public boolean removeSlice(SliceId sliceId) {
        AtomicBoolean result = new AtomicBoolean(true);

        getTrafficClasses(sliceId).forEach(tc -> {
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
        flowRuleService.applyFlowRules((FlowRule[]) buildFlowRules(deviceId, sliceId, tc, queueId).toArray());
        log.info("Add queue table flow on {} for slice {} tc {} queueId {}", deviceId, sliceId, tc, queueId);
    }

    private void removeQueueTable(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        flowRuleService.removeFlowRules((FlowRule[]) buildFlowRules(deviceId, sliceId, tc, queueId).toArray());
        log.info("Remove queue table flow on {} for slice {} tc {} queueId {}", deviceId, sliceId, tc, queueId);
    }

    private List<FlowRule> buildFlowRules(DeviceId deviceId, SliceId sliceId, TrafficClass tc, QueueId queueId) {
        List<FlowRule> flowRules = Lists.newArrayList();
        if (tc == TrafficClass.CONTROL) {
            flowRules.add(buildFlowRule(deviceId, sliceId, tc, queueId, Color.GREEN));
            flowRules.add(buildFlowRule(deviceId, sliceId, tc, queueId, Color.RED));
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
                .forTable(PiTableId.of(FABRIC_INGRESS_STATS_FLOWS.id()))
                .fromApp(appId)
                .withPriority(QOS_FLOW_PRIORITY)
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterionBuilder.build()).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piTableActionBuilder.build()).build())
                .makePermanent()
                .build();

        log.debug("{}", flowRule);
        return flowRule;
    }

    // TODO Expose REST API

    private class InternalSliceListener implements MapEventListener<SliceStoreKey, QueueId> {
        public void event(MapEvent<SliceStoreKey, QueueId> event) {
            // Distributed work based on QueueId. Consistent with InternalQueueListener
            if (workPartitionService.isMine(event.newValue().value(), toStringHasher())) {
                sliceExecutor.submit(() -> {
                    log.info("Processing slice event {}", event);
                    switch (event.type()) {
                        case INSERT:
                        case UPDATE:
                            deviceService.getAvailableDevices().forEach(device -> {
                                addQueueTable(device.id(),
                                        event.key().sliceId(), event.key().trafficClass(), event.newValue().value());
                            });
                            break;
                        case REMOVE:
                            deviceService.getAvailableDevices().forEach(device -> {
                                removeQueueTable(device.id(),
                                        event.key().sliceId(), event.key().trafficClass(), event.newValue().value());
                            });
                            break;
                        default:
                            break;
                    }
                });
            }
        }
    }

    private class InternalQueueListener implements MapEventListener<QueueId, QueueStoreValue> {
        public void event(MapEvent<QueueId, QueueStoreValue> event) {
            // Distributed work based on QueueId. Consistent with InternalSliceListener
            if (workPartitionService.isMine(event.key(), toStringHasher())) {
                sliceExecutor.submit(() -> {
                    log.info("Processing queue event {}", event);
                    switch (event.type()) {
                        case INSERT:
                        case UPDATE:
                            // TODO program queues. Today we assume queues are statically provisioned
                            break;
                        case REMOVE:
                            // TODO remove queues.  Today we assume queues are statically unprovisioned
                            break;
                        default:
                            break;
                    }
                });
            }
        }
    }

    // TODO Implement device listener. When device up, program queue table

    private static <K> Function<K, Long> toStringHasher() {
        return k -> Hashing.sha256().hashUnencodedChars(k.toString()).asLong();
    }
}
