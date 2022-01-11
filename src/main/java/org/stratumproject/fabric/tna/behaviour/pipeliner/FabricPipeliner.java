// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.onlab.packet.Ethernet;
import org.onlab.util.SharedExecutors;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.NextGroup;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.behaviour.PipelinerContext;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flowobjective.DefaultNextObjective;
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.FlowObjectiveStore;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.IdNextTreatment;
import org.onosproject.net.flowobjective.NextObjective;
import org.onosproject.net.flowobjective.NextTreatment;
import org.onosproject.net.flowobjective.Objective;
import org.onosproject.net.flowobjective.ObjectiveError;
import org.onosproject.net.group.DefaultGroup;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.Group;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupKey;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.PipeconfLoader;
import org.stratumproject.fabric.tna.behaviour.AbstractFabricHandlerBehavior;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.behaviour.Constants.DEFAULT_VLAN;
import static org.stratumproject.fabric.tna.behaviour.Constants.FWD_IPV4_ROUTING;
import static org.stratumproject.fabric.tna.behaviour.Constants.FWD_MPLS;
import static org.stratumproject.fabric.tna.behaviour.Constants.ONE;
import static org.stratumproject.fabric.tna.behaviour.Constants.PORT_TYPE_INTERNAL;
import static org.stratumproject.fabric.tna.behaviour.Constants.RECIRC_PORTS;
import static org.stratumproject.fabric.tna.behaviour.Constants.FAKE_V1MODEL_RECIRC_PORT;
import static org.stratumproject.fabric.tna.behaviour.Constants.ZERO;
import static org.stratumproject.fabric.tna.behaviour.Constants.PKT_IN_MIRROR_SESSION_ID;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.KRYO;

import static org.stratumproject.fabric.tna.behaviour.FabricUtils.outputPort;
import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;

/**
 * Pipeliner implementation for fabric-tna pipeline which uses ObjectiveTranslator
 * implementations to translate flow objectives for the different blocks,
 * filtering, forwarding and next.
 */
public class FabricPipeliner extends AbstractFabricHandlerBehavior
        implements Pipeliner {

    private static final Logger log = getLogger(FabricPipeliner.class);
    private static final int DEFAULT_FLOW_PRIORITY = 100;

    protected DeviceId deviceId;
    protected ApplicationId appId;
    protected FlowRuleService flowRuleService;
    protected GroupService groupService;
    protected FlowObjectiveStore flowObjectiveStore;
    protected CoreService coreService;

    private FilteringObjectiveTranslator filteringTranslator;
    private ForwardingObjectiveTranslator forwardingTranslator;
    private NextObjectiveTranslator nextTranslator;

    private final ExecutorService callbackExecutor = SharedExecutors.getPoolThreadExecutor();

    /**
     * Creates a new instance of this behavior with the given capabilities.
     *
     * @param capabilities capabilities
     */
    public FabricPipeliner(FabricCapabilities capabilities) {
        super(capabilities);
    }

    /**
     * Create a new instance of this behaviour. Used by the abstract projectable
     * model (i.e., {@link org.onosproject.net.Device#as(Class)}.
     */
    public FabricPipeliner() {
        super();
    }

    @Override
    public void init(DeviceId deviceId, PipelinerContext context) {
        this.deviceId = deviceId;
        this.flowRuleService = context.directory().get(FlowRuleService.class);
        this.groupService = context.directory().get(GroupService.class);
        this.flowObjectiveStore = context.directory().get(FlowObjectiveStore.class);
        this.filteringTranslator = new FilteringObjectiveTranslator(deviceId, capabilities);
        this.forwardingTranslator = new ForwardingObjectiveTranslator(deviceId, capabilities);
        this.nextTranslator = new NextObjectiveTranslator(deviceId, capabilities);
        this.coreService = context.directory().get(CoreService.class);
        this.appId = coreService.getAppId(PipeconfLoader.APP_NAME);

        initializePipeline();
    }

    @Override
    public void filter(FilteringObjective obj) {
        final ObjectiveTranslation result = filteringTranslator.translate(obj);
        handleResult(obj, result);
    }

    @Override
    public void forward(ForwardingObjective obj) {
        final ObjectiveTranslation result = forwardingTranslator.translate(obj);
        handleResult(obj, result);
    }

    @Override
    public void next(NextObjective obj) {
        if (obj.op() == Objective.Operation.VERIFY) {
            if (obj.type() != NextObjective.Type.HASHED) {
                log.warn("VERIFY operation not yet supported for NextObjective {}, will return failure :(",
                         obj.type());
                fail(obj, ObjectiveError.UNSUPPORTED);
                return;
            }

            if (log.isTraceEnabled()) {
                log.trace("Verify NextObjective {} in dev {}", obj, deviceId);
            }
            ObjectiveError error = handleVerify(obj);
            if (error == null) {
                success(obj);
            } else {
                fail(obj, error);
            }
            return;
        }

        if (obj.op() == Objective.Operation.MODIFY && obj.type() != NextObjective.Type.SIMPLE) {
            log.warn("MODIFY operation not yet supported for {} NextObjective, will return failure :(",
                     obj.type());
            if (log.isTraceEnabled()) {
                log.trace("Objective {}", obj);
            }
            fail(obj, ObjectiveError.UNSUPPORTED);
            return;
        }

        final ObjectiveTranslation result = nextTranslator.translate(obj);
        handleResult(obj, result);
    }

    @Override
    public void purgeAll(ApplicationId appId) {
        flowRuleService.purgeFlowRules(deviceId, appId);
        groupService.purgeGroupEntries(deviceId, appId);
        //FIXME: purge flowObjectiveStore as well when addressing SDFAB-250.
        // Currently we don't have enough information in the store to purge by app and device ID
    }

    @Override
    public List<String> getNextMappings(NextGroup nextGroup) {
        final FabricNextGroup fabricNextGroup = KRYO.deserialize(nextGroup.data());
        return fabricNextGroup.nextMappings().stream()
                .map(m -> format("%s -> %s", fabricNextGroup.type(), m))
                .collect(Collectors.toList());
    }

    protected void initializePipeline() {
        // Set up CPU port for packet-in/out. For packet-out, we support only
        // IPv4 routing when do_forwarding=1.
        final int cpuPort = capabilities.cpuPort().get();
        flowRuleService.applyFlowRules(
                egressSwitchInfoRule(cpuPort),
                ingressVlanRule(cpuPort, false, DEFAULT_VLAN, PORT_TYPE_INTERNAL),
                fwdClassifierRule(cpuPort, null, Ethernet.TYPE_IPV4, FWD_IPV4_ROUTING,
                                  DEFAULT_FLOW_PRIORITY));
        // Set up mirror session for packet-in.
        groupService.addGroup(packetInCloneGroup());

        // Set up recirculation ports as untagged (used for INT reports and
        // UE-to-UE in SPGW pipe).
        List<Integer> recircPorts = capabilities.isArchTna() ? RECIRC_PORTS : FAKE_V1MODEL_RECIRC_PORT;
        // Setting recirculation ports only for TNA. When running for bmv2, a single fake recirculation port is used.
        recircPorts.forEach(port -> {
            flowRuleService.applyFlowRules(
                    ingressVlanRule(port, false, DEFAULT_VLAN, PORT_TYPE_INTERNAL),
                    egressVlanRule(port, DEFAULT_VLAN, false),
                    fwdClassifierRule(port, null, Ethernet.TYPE_IPV4, FWD_IPV4_ROUTING,
                                      DEFAULT_FLOW_PRIORITY),
                    // Use higher priority for MPLS rule since the one for IPv4
                    // matches all IPv4 traffic independently of the eth_type.
                    fwdClassifierRule(port, Ethernet.MPLS_UNICAST, Ethernet.TYPE_IPV4, FWD_MPLS,
                                      DEFAULT_FLOW_PRIORITY + 10));
        });
        // TODO: slicing.p4 DSCP tables for PORT_TYPE_INTERNAL
        //  PORT_TYPE_INTERNAL includes packet-outs that's part of the SYSTEM TC
        //  and should be directed to the System Queue (SDFAB-520), and recirculation
        //  traffic (SDFAB-398).
    }

    private void handleResult(Objective obj, ObjectiveTranslation result) {
        if (result.error().isPresent()) {
            fail(obj, result.error().get());
            return;
        }
        processGroups(obj, result.groups());
        processFlows(obj, result.flowRules());
        if (obj instanceof NextObjective) {
            handleNextGroup((NextObjective) obj);
        }
        success(obj);
    }

    private void handleNextGroup(NextObjective obj) {
        // FIXME SDFAB-250 ADD_TO and REMOVE_FROM should update the content
        switch (obj.op()) {
            case REMOVE:
                removeNextGroup(obj);
                break;
            case ADD:
            case ADD_TO_EXISTING:
            case REMOVE_FROM_EXISTING:
            case MODIFY:
                putNextGroup(obj);
                break;
            case VERIFY:
                break;
            default:
                log.error("Unknown NextObjective operation '{}'", obj.op());
        }
    }

    private void processFlows(Objective objective, Collection<FlowRule> flowRules) {
        if (flowRules.isEmpty()) {
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Objective {} -> Flows {}", objective, flowRules);
        }

        final FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        switch (objective.op()) {
            case ADD:
            case ADD_TO_EXISTING:
            case MODIFY:
                flowRules.forEach(ops::add);
                break;
            case REMOVE:
            case REMOVE_FROM_EXISTING:
                flowRules.forEach(ops::remove);
                break;
            default:
                log.warn("Unsupported Objective operation {}", objective.op());
                return;
        }
        flowRuleService.apply(ops.build());
    }

    private void processGroups(Objective objective, Collection<GroupDescription> groups) {
        if (groups.isEmpty()) {
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Objective {} -> Groups {}", objective, groups);
        }

        switch (objective.op()) {
            case ADD:
                groups.forEach(groupService::addGroup);
                break;
            case REMOVE:
                groups.forEach(group -> groupService.removeGroup(
                        deviceId, group.appCookie(), objective.appId()));
                break;
            case ADD_TO_EXISTING:
                groups.forEach(group -> groupService.addBucketsToGroup(
                        deviceId, group.appCookie(), group.buckets(),
                        group.appCookie(), group.appId())
                );
                break;
            case MODIFY:
                // Modify is only supported for simple next objective
                // Replace group bucket directly
                groups.forEach(group -> groupService.setBucketsForGroup(
                        deviceId, group.appCookie(), group.buckets(),
                        group.appCookie(), group.appId()));
                break;
            case REMOVE_FROM_EXISTING:
                groups.forEach(group -> groupService.removeBucketsFromGroup(
                        deviceId, group.appCookie(), group.buckets(),
                        group.appCookie(), group.appId())
                );
                break;
            default:
                log.warn("Unsupported Objective operation {}", objective.op());
        }
    }

    private void fail(Objective objective, ObjectiveError error) {
        CompletableFuture.runAsync(
                () -> objective.context().ifPresent(
                        ctx -> ctx.onError(objective, error)), callbackExecutor);

    }


    private void success(Objective objective) {
        CompletableFuture.runAsync(
                () -> objective.context().ifPresent(
                        ctx -> ctx.onSuccess(objective)), callbackExecutor);
    }

    private void removeNextGroup(NextObjective obj) {
        final NextGroup removed = flowObjectiveStore.removeNextGroup(obj.id());
        if (removed == null) {
            log.debug("NextGroup {} was not found in FlowObjectiveStore", obj.id());
        }
    }

    private void putNextGroup(NextObjective obj) {
        final List<String> nextMappings = obj.nextTreatments().stream()
                .map(this::nextTreatmentToMappingString)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        final FabricNextGroup nextGroup = new FabricNextGroup(obj.type(), nextMappings);
        flowObjectiveStore.putNextGroup(obj.id(), nextGroup);
    }

    private String nextTreatmentToMappingString(NextTreatment n) {
        switch (n.type()) {
            case TREATMENT:
                final PortNumber p = outputPort(n);
                return p == null ? "UNKNOWN"
                        : format("OUTPUT:%s", p.toString());
            case ID:
                final IdNextTreatment id = (IdNextTreatment) n;
                return format("NEXT_ID:%d", id.nextId());
            default:
                log.warn("Unknown NextTreatment type '{}'", n.type());
                return "???";
        }
    }

    public FlowRule egressSwitchInfoRule(int cpuPort) {
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                                       .withId(P4InfoConstants.FABRIC_EGRESS_PKT_IO_EGRESS_SET_SWITCH_INFO)
                                       .withParameter(new PiActionParam(P4InfoConstants.CPU_PORT, cpuPort))
                                       .build())
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withTreatment(treatment)
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .fromApp(appId)
                .makePermanent()
                .forTable(P4InfoConstants.FABRIC_EGRESS_PKT_IO_EGRESS_SWITCH_INFO)
                .build();
    }

    public FlowRule ingressVlanRule(long port, boolean vlanValid, int vlanId, byte portType) {
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .add(Criteria.matchInPort(PortNumber.portNumber(port)))
                .add(PiCriterion.builder()
                             .matchExact(P4InfoConstants.HDR_VLAN_IS_VALID, vlanValid ? ONE : ZERO)
                             .build())
                .build();
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                                       .withId(vlanValid ?
                                           P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT
                                           : P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)
                                       .withParameter(new PiActionParam(P4InfoConstants.VLAN_ID, vlanId))
                                       .withParameter(new PiActionParam(P4InfoConstants.PORT_TYPE, portType))
                                       .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN)
                .makePermanent()
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .forDevice(deviceId)
                .fromApp(appId)
                .build();
    }

    public FlowRule fwdClassifierRule(int port, Short ethType, short ipEthType, byte fwdType, int priority) {
        final TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchInPort(PortNumber.portNumber(port))
                .matchPi(PiCriterion.builder()
                                 .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, ipEthType)
                                 .build());
        if (ethType != null) {
            selectorBuilder.matchEthType(ethType);
        }
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                                       .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                                       .withParameter(new PiActionParam(
                                               P4InfoConstants.FWD_TYPE, fwdType))
                                       .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)
                .makePermanent()
                .withPriority(priority)
                .forDevice(deviceId)
                .fromApp(appId)
                .build();
    }

    public FlowRule egressVlanRule(int port, int vlanId, boolean tagged) {
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .add(PiCriterion.builder()
                             .matchExact(P4InfoConstants.HDR_VLAN_ID, vlanId)
                             .matchExact(P4InfoConstants.HDR_EG_PORT, port)
                             .build())
                .build();
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder()
                                       .withId(tagged ?
                                                       P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_PUSH_VLAN
                                                       : P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_POP_VLAN)
                                       .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .forTable(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN)
                .makePermanent()
                .withPriority(DEFAULT_FLOW_PRIORITY)
                .forDevice(deviceId)
                .fromApp(appId)
                .build();
    }

    GroupDescription packetInCloneGroup() {
        final List<GroupBucket> buckets = ImmutableList.of(
                createCloneGroupBucket(DefaultTrafficTreatment.builder()
                                               .setOutput(PortNumber.CONTROLLER)
                                               .build()));
        return new DefaultGroupDescription(
                deviceId, GroupDescription.Type.CLONE,
                new GroupBuckets(buckets),
                new DefaultGroupKey(KRYO.serialize(PKT_IN_MIRROR_SESSION_ID)),
                PKT_IN_MIRROR_SESSION_ID, appId);
    }

    private ObjectiveError handleVerify(NextObjective nextObjective) {
        Map<GroupBucket, FlowRule> bucketsToFlows = getBucketToFlowMapping(nextObjective);
        if (bucketsToFlows.isEmpty() && !nextObjective.nextTreatments().isEmpty()) {
            log.warn("VERIFY failed due to translation error, bucketsToFlows is empty");
            return ObjectiveError.BADPARAMS;
        }

        if (log.isTraceEnabled()) {
            log.trace("Mapping bucketsToFlows {} has been generated ", bucketsToFlows);
        }

        GroupKey groupKey = nextTranslator.getGroupKey(nextObjective);
        if (groupKey == null) {
            log.warn("VERIFY failed due to translation error, unable to determine group key");
            return ObjectiveError.BADPARAMS;
        }
        Group groupFromStore = groupService.getGroup(deviceId, groupKey);
        if (groupFromStore == null) {
            log.warn("VERIFY failed due to missing group in the store");
            return ObjectiveError.GROUPMISSING;
        }

        // Looking for duplicate buckets - remove them by using a set and comparing size after/before
        Set<GroupBucket> bucketsFromStore = Sets.newHashSet(groupFromStore.buckets().buckets());
        if (groupFromStore.buckets().buckets().size() > bucketsFromStore.size()) {
            log.warn("Duplicated buckets detected in device:{}, nextId:{}, before-size" +
                             ":{} after-size:{} .. correcting", deviceId,
                     nextObjective.id(), groupFromStore.buckets().buckets().size(), bucketsFromStore.size());
            final GroupBuckets bucketToSet = new GroupBuckets(Lists.newArrayList(bucketsFromStore));
            groupService.setBucketsForGroup(deviceId, groupKey, bucketToSet, groupKey, nextObjective.appId());
            // Forge temporary the group to avoid race condition with the store
            groupFromStore = new DefaultGroup(groupFromStore.id(), deviceId, groupFromStore.type(), bucketToSet);
        }

        // Looking for buckets missing in the group but defined in the next
        Map<GroupBucket, FlowRule> toAdd = Maps.newHashMap();
        for (Map.Entry<GroupBucket, FlowRule> entry : bucketsToFlows.entrySet()) {
            if (!groupFromStore.buckets().buckets().contains(entry.getKey())) {
                toAdd.put(entry.getKey(), entry.getValue());
            }
        }

        // Looking for buckets missing in the next but defined in the group
        // FIXME SDFAB-250 we cannot remove associated egress flows
        List<GroupBucket> toRemove = Lists.newArrayList();
        groupFromStore.buckets().buckets().forEach(bucket -> {
            if (!bucketsToFlows.containsKey(bucket)) {
                toRemove.add(bucket);
            }
        });

        if (!toAdd.isEmpty() || !toRemove.isEmpty()) {
            log.warn("Mismatch detected in device:{}, nextId:{}, groupFromTranslation-size:{} " +
                             "groupFromStore-size:{} toAdd-size:{} toRemove-size: {} .. correcting",
                     deviceId, nextObjective.id(), bucketsToFlows.size(), groupFromStore.buckets().buckets().size(),
                     toAdd.size(), toRemove.size());
        }

        if (!toAdd.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("Adding missing buckets {} and flows {}", toAdd.keySet(), toAdd.values());
            }
            final FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
            final FlowRule dummyFlow = getDummyFlow(nextObjective);
            toAdd.values().stream()
                    .filter(flowRule -> !flowRule.equals(dummyFlow))
                    .forEach(ops::add);
            final GroupBuckets bucketsToAdd = new GroupBuckets(Lists.newArrayList(toAdd.keySet()));
            groupService.addBucketsToGroup(deviceId, groupKey, bucketsToAdd, groupKey, nextObjective.appId());
            flowRuleService.apply(ops.build());
        }

        if (!toRemove.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("Removing stale buckets {}", toRemove);
            }
            final GroupBuckets bucketsToRemove = new GroupBuckets(toRemove);
            groupService.removeBucketsFromGroup(deviceId, groupKey, bucketsToRemove, groupKey,
                                                nextObjective.appId());
        }

        return null;
    }

    private Map<GroupBucket, FlowRule> getBucketToFlowMapping(NextObjective nextObjective) {
        Map<GroupBucket, FlowRule> mapping = Maps.newHashMap();
        NextObjective newNextObjective;
        ObjectiveTranslation result;
        FlowRule dummyFlow = getDummyFlow(nextObjective);
        FlowRule egFlow;
        GroupBucket groupBucket;
        GroupDescription group;
        for (NextTreatment nextTreatment : nextObjective.nextTreatments()) {
            newNextObjective = DefaultNextObjective.builder()
                    .withId(nextObjective.id())
                    .withType(nextObjective.type())
                    .fromApp(nextObjective.appId())
                    .withMeta(nextObjective.meta())
                    .addTreatment(nextTreatment)
                    .verify();
            result = nextTranslator.translate(newNextObjective);
            if ((result.groups().isEmpty() && result.flowRules().isEmpty()) ||
                    result.groups().size() > 1) {
                return Collections.emptyMap();
            }
            group = result.groups().iterator().next();
            egFlow = result.flowRules().stream()
                    .filter(flowRule -> flowRule.table().equals(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN))
                    .findFirst()
                    .orElse(null);
            if (group.buckets().buckets().isEmpty() || group.buckets().buckets().size() > 1) {
                return Collections.emptyMap();
            }
            groupBucket = group.buckets().buckets().iterator().next();
            if (egFlow == null) {
                mapping.put(groupBucket, dummyFlow);
            } else {
                mapping.put(groupBucket, egFlow);
            }
        }
        return mapping;
    }

    private FlowRule getDummyFlow(NextObjective nextObjective) {
        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(0)
                .fromApp(nextObjective.appId())
                .withPriority(1)
                .withSelector(DefaultTrafficSelector.emptySelector())
                .makePermanent()
                .build();
    }

    /**
     * NextGroup implementation.
     */
    public static class FabricNextGroup implements NextGroup {
        // FIXME SDFAB-250 they are not very useful nor technically correct
        private final NextObjective.Type type;
        private final List<String> nextMappings;

        FabricNextGroup(NextObjective.Type type, List<String> nextMappings) {
            this.type = type;
            this.nextMappings = ImmutableList.copyOf(nextMappings);
        }

        NextObjective.Type type() {
            return type;
        }

        Collection<String> nextMappings() {
            return nextMappings;
        }

        @Override
        public byte[] data() {
            return KRYO.serialize(this);
        }
    }
}
