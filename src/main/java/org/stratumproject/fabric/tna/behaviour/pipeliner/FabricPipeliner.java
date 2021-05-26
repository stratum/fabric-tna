// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import com.google.common.collect.ImmutableList;
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
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.FlowObjectiveStore;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.IdNextTreatment;
import org.onosproject.net.flowobjective.NextObjective;
import org.onosproject.net.flowobjective.NextTreatment;
import org.onosproject.net.flowobjective.Objective;
import org.onosproject.net.flowobjective.ObjectiveError;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.PipeconfLoader;
import org.stratumproject.fabric.tna.behaviour.AbstractFabricHandlerBehavior;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
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
import static org.stratumproject.fabric.tna.behaviour.Constants.ZERO;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.KRYO;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.outputPort;

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
            // TODO: support VERIFY operation
            log.debug("VERIFY operation not yet supported for NextObjective, will return success");
            success(obj);
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
        // Set up recirculation ports as untagged (used for INT reports and
        // UE-to-UE in SPGW pipe).
        RECIRC_PORTS.forEach(port -> {
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
            selectorBuilder.matchEthType(Ethernet.MPLS_UNICAST);
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

    /**
     * NextGroup implementation.
     */
    public static class FabricNextGroup implements NextGroup {

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
