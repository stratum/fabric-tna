// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;
import org.onlab.util.KryoNamespace;
import org.onosproject.cluster.ClusterService;
import org.onosproject.cluster.NodeId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.intent.WorkPartitionService;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiExactFieldMatch;
import org.onosproject.net.pi.runtime.PiFieldMatch;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.DistributedSet;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.SetEvent;
import org.onosproject.store.service.SetEventListener;
import org.onosproject.store.service.StorageService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_STATS_FLOWS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_STATS_FLOWS;

@Component(immediate = true, service = StatisticService.class)
public class StatisticManager implements StatisticService {
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ClusterService clusterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected WorkPartitionService workPartitionService;

    private static final Logger log = getLogger(StatisticManager.class);
    private static final String APP_NAME = "org.stratumproject.fabric.tna.stats";
    private static final long PORT_MASK = 0x1ffL;
    private static final long POLL_INTERVAL_MS = 1000;

    private ApplicationId appId;

    // Distribited set storing current monitoring criteria
    private DistributedSet<StatisticKey> statsStore;
    private SetEventListener<StatisticKey> statsListener;
    private ExecutorService statsEventExecutor;

    // Local map storing counters
    private Map<StatisticKey, Map<StatisticDataKey, StatisticDataValue>> statsMap = Maps.newConcurrentMap();
    private ScheduledExecutorService statsCollectorExecutor;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);

        KryoNamespace.Builder serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(StatisticKey.class);

        statsStore = storageService.<StatisticKey>setBuilder()
                .withName("fabric-tna-stats")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build().asDistributedSet();
        statsListener = new InternalSetEventListener();
        statsEventExecutor = Executors.newSingleThreadExecutor(
                groupedThreads("fabric-tna-stats-event", "%d", log));
        statsStore.addListener(statsListener);

        statsCollectorExecutor = Executors.newSingleThreadScheduledExecutor(
                groupedThreads("fabric-tna-stats-collector", "%d", log));
        statsCollectorExecutor.scheduleAtFixedRate(new InternalStatsCollector(),
                0, POLL_INTERVAL_MS, TimeUnit.MILLISECONDS);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        statsStore.removeListener(statsListener);
        statsEventExecutor.shutdown();

        statsStore.forEach(this::removeStatsInternal);
        statsStore.clear();

        statsCollectorExecutor.shutdown();

        log.info("Stopped");
    }

    @Override
    public void addMonitor(TrafficSelector selector, int id) {
        if (statsStore.stream().anyMatch(key -> key.id() == id)) {
            log.warn("Monitor with same id {} exist. Skipping", id);
            return;
        }

        StatisticKey key = StatisticKey.builder()
                .withSelector(selector)
                .withId(id)
                .build();
        statsStore.add(key);
        log.info("Adding selector {}", key);
    }

    @Override
    public void removeMonitor(TrafficSelector selector, int id) {
        StatisticKey key = StatisticKey.builder()
                .withSelector(selector)
                .withId(id)
                .build();
        statsStore.remove(key);
        log.info("Removing selector {}", selector);
    }

    @Override
    public Set<StatisticKey> getMonitors() {
        return Set.copyOf(statsStore);
    }

    @Override
    public Map<StatisticDataKey, StatisticDataValue> getStats(int id) {
        StatisticKey key = getMonitors().stream()
                .filter(k -> k.id() == id)
                .findFirst().orElse(null);
        if (key == null) {
            return null;
        } else {
            return Map.copyOf(statsMap.get(key));
        }
    }

    private void addStatsInternal(StatisticKey key) {
        FlowRule[] flowRules = buildFlowRules(key).toArray(FlowRule[]::new);
        flowRuleService.applyFlowRules(flowRules);
        log.info("Apply {} flows", flowRules.length);
    }

    private void removeStatsInternal(StatisticKey key) {
        FlowRule[] flowRules = buildFlowRules(key).toArray(FlowRule[]::new);
        flowRuleService.removeFlowRules(flowRules);
        statsMap.remove(key);
        log.info("Remove {} flows", flowRules.length);
    }

    // Prepare flow rules for both ingress and egress
    private List<FlowRule> buildFlowRules(StatisticKey key) {
        // All possible ports in current topology
        List<Port> ports = StreamSupport.stream(deviceService.getAvailableDevices().spliterator(), true)
                .map(Device::id)
                .map(deviceService::getPorts)
                .flatMap(List<Port>::stream)
                .collect(Collectors.toList());

        // Prepare ingress and egress flow rule per port
        List<FlowRule> flowRules = Lists.newArrayList();
        ports.stream().forEach(port -> {
            DeviceId deviceId = (DeviceId) port.element().id();
            PortNumber portNumber = port.number();
            log.debug("Processing flow rule for {}/{}", deviceId, portNumber);

            // Prepare PiCriterion
            PiCriterion ingressPiCriterion = PiCriterion.builder()
                    .matchExact(P4InfoConstants.HDR_IG_PORT, portNumber.toLong())
                    .build();
            PiCriterion egressPiCriterion = PiCriterion.builder()
                    .matchExact(P4InfoConstants.HDR_STATS_FLOW_ID, key.id())
                    .matchExact(P4InfoConstants.HDR_EG_PORT, portNumber.toLong())
                    .build();

            // Prepare PiTableAction
            PiTableAction ingressPiTableAction = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_INGRESS_STATS_COUNT)
                    .withParameter(new PiActionParam(P4InfoConstants.FLOW_ID, key.id()))
                    .build();
            PiTableAction egressPiTableAction = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_EGRESS_STATS_COUNT)
                    .build();

            // Prepare FlowRule
            FlowRule ingressFlowRule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .forTable(PiTableId.of(FABRIC_INGRESS_STATS_FLOWS.id()))
                    .fromApp(appId)
                    .withPriority(key.id())
                    .withSelector(DefaultTrafficSelector.builder(key.selector()).matchPi(ingressPiCriterion).build())
                    .withTreatment(DefaultTrafficTreatment.builder().piTableAction(ingressPiTableAction).build())
                    .makePermanent()
                    .build();
            FlowRule egressFlowRule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .forTable(PiTableId.of(FABRIC_EGRESS_STATS_FLOWS.id()))
                    .fromApp(appId)
                    .withPriority(key.id())
                    .withSelector(DefaultTrafficSelector.builder().matchPi(egressPiCriterion).build())
                    .withTreatment(DefaultTrafficTreatment.builder().piTableAction(egressPiTableAction).build())
                    .makePermanent()
                    .build();
            flowRules.add(ingressFlowRule);
            flowRules.add(egressFlowRule);
        });

        log.debug("Total {} flow rules", flowRules.size());
        return flowRules;
    }

    private class InternalSetEventListener implements SetEventListener<StatisticKey> {
        @Override
        public void event(SetEvent<StatisticKey> event) {
            if (isLeader(event.entry())) {
                statsEventExecutor.submit(() -> {
                    log.debug("Processing event {}", event);
                    switch (event.type()) {
                        case ADD:
                            addStatsInternal(event.entry());
                            break;
                        case REMOVE:
                            removeStatsInternal(event.entry());
                            break;
                        default:
                            break;
                    }
                });
            }
        }

        private boolean isLeader(StatisticKey key) {
            final NodeId currentNodeId = clusterService.getLocalNode().id();
            final NodeId leaderNodeId = workPartitionService.getLeader(key,
                    k -> Hashing.sha256().hashUnencodedChars(k.toString()).asLong());
            if (leaderNodeId == null) {
                log.error("Failed to elect a leader for {}", key);
                return false;
            }
            return currentNodeId.equals(leaderNodeId);
        }
    }

    private class InternalStatsCollector implements Runnable {
        @Override
        public void run() {
            flowRuleService.getFlowEntriesById(appId).forEach(flowEntry -> {
                TrafficSelector flowSelector = flowEntry.selector();

                TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

                StatisticKey.Builder keyBuilder = StatisticKey.builder()
                        .withId(flowEntry.priority());
                StatisticDataKey.Builder dataKeyBuilder = StatisticDataKey.builder()
                        .withDeviceId(flowEntry.deviceId());
                StatisticDataValue.Builder dataValueBuilder = StatisticDataValue.builder();

                StatisticDataKey.Type type;
                PiMatchFieldId piMatchFieldId;
                if (flowEntry.table().equals(FABRIC_INGRESS_STATS_FLOWS)) {
                    type = StatisticDataKey.Type.INGRESS;
                    piMatchFieldId = P4InfoConstants.HDR_IG_PORT;
                } else if (flowEntry.table().equals(FABRIC_EGRESS_STATS_FLOWS)) {
                    type = StatisticDataKey.Type.EGRESS;
                    piMatchFieldId = P4InfoConstants.HDR_EG_PORT;
                } else {
                    log.debug("Ignore flow that does not belong to ingress nor egress stat table");
                    log.debug("selector={}, table={}", flowSelector, flowEntry.table());
                    return;
                }

                for (Criterion criterion : flowSelector.criteria()) {
                    if (criterion.type() == Criterion.Type.PROTOCOL_INDEPENDENT) {
                        // Parse ingress or egress port information from piCriterion
                        PiCriterion piCriterion = (PiCriterion) criterion;
                        piCriterion.fieldMatches().forEach(piFieldMatch -> {
                            if (piFieldMatch.fieldId().equals(piMatchFieldId)) {
                                dataKeyBuilder.withType(type);
                                dataKeyBuilder.withPortNumber(getPortNumber(piFieldMatch));
                            } else if (piFieldMatch.fieldId().equals(P4InfoConstants.HDR_STATS_FLOW_ID)) {
                                // This flow is from egress table
                                // Extract stat_flow_id
                                PiExactFieldMatch piExactFieldMatch = (PiExactFieldMatch) piFieldMatch;
                                int statFlowId = ByteBuffer.wrap(piExactFieldMatch.value().asArray()).getInt();
                                // Translate stats_flow_id back to original selector
                                statsStore.stream().filter(key -> key.id() == statFlowId)
                                        .map(StatisticKey::selector)
                                        .map(TrafficSelector::criteria)
                                        .flatMap(Set::stream)
                                        .forEach(selectorBuilder::add);
                            } else {
                                log.warn("Unexpected PiCriterion {} in flowEntry {}", piCriterion, flowEntry);
                            }
                        });
                    } else {
                        // Retain other type of criterion
                        selectorBuilder.add(criterion);
                    }
                }

                StatisticKey key = keyBuilder
                        .withSelector(selectorBuilder.build())
                        .build();
                StatisticDataKey dataKey = dataKeyBuilder.build();
                log.debug("key={}", key);
                log.debug("dataKey={}", dataKey);

                statsMap.compute(key, (k1, v1) -> {
                    log.debug("k1={}, v1={}", k1, v1);
                    if (v1 == null) {
                        v1 = Maps.newConcurrentMap();
                    }
                    v1.compute(dataKey, (k2, v2) -> {
                        log.debug("k2={}, v2={}", k2, v2);
                        if (v2 != null && v2.timeMs() == flowEntry.lastSeen()) {
                            log.debug("Flow stats unchanged for key={}, dataKey={}", key, dataKey);
                            return v2;
                        }
                        StatisticDataValue dataValue = dataValueBuilder
                                // Set previous value if exists, or use current value otherwise.
                                .withPrevByteCount(v2 != null ? v2.byteCount() : flowEntry.bytes())
                                .withPrevPacketCount(v2 != null ? v2.packetCount() : flowEntry.packets())
                                .withPrevTimeMs(v2 != null ? v2.timeMs() : flowEntry.lastSeen())
                                .withByteCount(flowEntry.bytes())
                                .withPacketCount(flowEntry.packets())
                                .withTimeMs(flowEntry.lastSeen())
                                .build();
                        log.debug("Update stats for key={}, dataKey={}, dataValue={}", key, dataKey, dataValue);
                        return dataValue;
                    });
                    return v1;
                });
            });
        }

        private PortNumber getPortNumber(PiFieldMatch piFieldMatch) {
            PiExactFieldMatch piExactFieldMatch = (PiExactFieldMatch) piFieldMatch;
            return PortNumber.portNumber(ByteBuffer.wrap(piExactFieldMatch.value().asArray()).getLong());
        }
    }

}
