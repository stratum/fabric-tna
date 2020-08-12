// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.inbandtelemetry.IntDeviceConfig;
import org.onosproject.net.behaviour.inbandtelemetry.IntObjective;
import org.onosproject.net.behaviour.inbandtelemetry.IntProgrammable;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TableId;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupKey;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.stratumproject.fabric.tna.PipeconfLoader;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.KRYO;

/**
 * Implementation of INT programmable behavior for fabric.p4.
 */
public class FabricIntProgrammable extends AbstractFabricHandlerBehavior
        implements IntProgrammable {

    private static final int DEFAULT_PRIORITY = 10000;
    private static final List<Integer> REPORT_MIRROR_SESSION_ID_LIST = ImmutableList.of(300, 301, 302, 303);
    private static final List<Integer> RECIRC_PORTS = ImmutableList.of(0x44, 0xc4, 0x144, 0x1c4);

    private static final Set<Criterion.Type> SUPPORTED_CRITERION = Sets.newHashSet(
            Criterion.Type.IPV4_DST, Criterion.Type.IPV4_SRC,
            Criterion.Type.UDP_SRC, Criterion.Type.UDP_DST,
            Criterion.Type.TCP_SRC, Criterion.Type.TCP_DST);

    private static final Set<TableId> TABLES_TO_CLEANUP = Sets.newHashSet(
            P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_COLLECTOR,
            P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_REPORT
    );

    private FlowRuleService flowRuleService;
    private GroupService groupService;
    private NetworkConfigService cfgService;

    private DeviceId deviceId;
    private ApplicationId appId;

    /**
     * Creates a new instance of this behavior with the given capabilities.
     *
     * @param capabilities capabilities
     */
    protected FabricIntProgrammable(FabricCapabilities capabilities) {
        super(capabilities);
    }

    /**
     * Create a new instance of this behaviour. Used by the abstract projectable model (i.e., {@link
     * org.onosproject.net.Device#as(Class)}.
     */
    public FabricIntProgrammable() {
        super();
    }

    private boolean setupBehaviour() {
        deviceId = this.data().deviceId();
        flowRuleService = handler().get(FlowRuleService.class);
        groupService = handler().get(GroupService.class);
        cfgService = handler().get(NetworkConfigService.class);
        final CoreService coreService = handler().get(CoreService.class);
        appId = coreService.getAppId(PipeconfLoader.APP_NAME);
        if (appId == null) {
            log.warn("Application ID is null. Cannot initialize behaviour.");
            return false;
        }
        return true;
    }

    @Override
    public boolean init() {
        if (!setupBehaviour()) {
            return false;
        }

        // Mirroring sessions for report cloning.
        for (int pipeId = 0; pipeId < REPORT_MIRROR_SESSION_ID_LIST.size(); pipeId++) {
            final int reportSessionId = REPORT_MIRROR_SESSION_ID_LIST.get(pipeId);
            final List<GroupBucket> bucketList = ImmutableList.of(
                    createCloneGroupBucket(DefaultTrafficTreatment.builder()
                            .setOutput(PortNumber.portNumber(RECIRC_PORTS.get(pipeId)))
                            .build()));
            final GroupKey groupKey = new DefaultGroupKey(
                    KRYO.serialize(reportSessionId));
            final GroupDescription groupDescription = new DefaultGroupDescription(
                    deviceId, GroupDescription.Type.CLONE,
                    new GroupBuckets(bucketList),
                    groupKey, reportSessionId, appId);
            groupService.addGroup(groupDescription);

            // TODO: Now table entries in this this table are static
            //            final PiAction setMirrorIdAction = PiAction.builder()
            //                    .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_INT_SINK_SET_MIRROR_SESSION_ID)
            //                    .withParameter(new PiActionParam(P4InfoConstants.SID, reportSessionId))
            //                    .build();
            //            final TrafficTreatment setMirrorIdTreatment = DefaultTrafficTreatment.builder()
            //                    .piTableAction(setMirrorIdAction)
            //                    .build();
            //            final TrafficSelector pipeIdSelector = DefaultTrafficSelector.builder()
            //                    .matchPi(PiCriterion.builder().matchExact(
            //                            P4InfoConstants.HDR_PIPE_ID,
            //                            pipeId
            //                    ).build())
            //                    .build();
            //            final FlowRUle setMirrorIdRule = DefaultFlowRule.builder()
            //                    .withSelector(pipeIdSelector)
            //                    .withTreatment(setMirrorIdTreatment)
            //                    .fromApp(appId)
            //                    .withPriority(DEFAULT_PRIORITY)
            //                    .makePermanent()
            //                    .forDevice(deviceId)
            //                    .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_INT_SINK_TB_SET_MIRROR_SESSION_ID)
            //                    .build();
            //             flowRuleService.applyFlowRules(setMirrorIdRule);
        }

        return true;
    }

    @Override
    public boolean setSourcePort(PortNumber port) {
        return setupBehaviour();
    }

    @Override
    public boolean setSinkPort(PortNumber port) {
        return setupBehaviour();
    }

    @Override
    public boolean addIntObjective(IntObjective obj) {

        if (!setupBehaviour()) {
            return false;
        }

        return processIntObjective(obj, true);
    }

    @Override
    public boolean removeIntObjective(IntObjective obj) {

        if (!setupBehaviour()) {
            return false;
        }

        return processIntObjective(obj, false);
    }

    @Override
    public boolean setupIntConfig(IntDeviceConfig config) {

        if (!setupBehaviour()) {
            return false;
        }

        return setupIntReportInternal(config);
    }

    @Override
    public void cleanup() {

        if (!setupBehaviour()) {
            return;
        }

        StreamSupport.stream(flowRuleService.getFlowEntries(
                data().deviceId()).spliterator(), false)
                .filter(f -> TABLES_TO_CLEANUP.contains(f.table()))
                .forEach(flowRuleService::removeFlowRules);

        // FIXME: saw issue with clone groups disappearing when inserting.deleting watchlist rules
        // for (final Integer reportSessionId : REPORT_MIRROR_SESSION_ID_LIST) {
        //     final var groupKey = new DefaultGroupKey(
        //             KRYO.serialize(reportSessionId));
        //     groupService.removeGroup(deviceId, groupKey, appId);
        // }
    }

    @Override
    public boolean supportsFunctionality(IntFunctionality functionality) {
        return functionality == IntFunctionality.SOURCE ||
                functionality == IntFunctionality.TRANSIT ||
                functionality == IntFunctionality.SINK;
    }

    private FlowRule buildCollectorEntry(IntObjective obj) {
        final SegmentRoutingDeviceConfig cfg = cfgService.getConfig(
                deviceId, SegmentRoutingDeviceConfig.class);
        if (cfg == null) {
            log.warn("Missing SegmentRoutingDeviceConfig config for {}", deviceId);
            return null;
        }

        final PiActionParam switchIdParam = new PiActionParam(
                P4InfoConstants.SWITCH_ID, cfg.nodeSidIPv4());

        final PiAction collectorAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_COLLECT)
                .withParameter(switchIdParam)
                .build();

        final TrafficTreatment collectorTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(collectorAction)
                .build();

        final TrafficSelector selector = buildCollectorSelector(obj.selector().criteria());

        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(collectorTreatment)
                .withPriority(DEFAULT_PRIORITY)
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_COLLECTOR)
                .fromApp(appId)
                .makePermanent()
                .build();
    }

    private TrafficSelector buildCollectorSelector(Set<Criterion> criteria) {
        TrafficSelector.Builder builder = DefaultTrafficSelector.builder();
        for (Criterion criterion : criteria) {
            switch (criterion.type()) {
                case IPV4_SRC:
                    builder.matchIPSrc(((IPCriterion) criterion).ip());
                    break;
                case IPV4_DST:
                    builder.matchIPDst(((IPCriterion) criterion).ip());
                    break;
                case TCP_SRC:
                    // TODO: Match a range of TCP port
                    builder.matchPi(
                            PiCriterion.builder().matchRange(
                                    P4InfoConstants.HDR_L4_SPORT,
                                    ((TcpPortCriterion) criterion).tcpPort().toInt(),
                                    ((TcpPortCriterion) criterion).tcpPort().toInt())
                                    .build());
                    break;
                case UDP_SRC:
                    // TODO: Match a range of UDP port
                    builder.matchPi(
                            PiCriterion.builder().matchTernary(
                                    P4InfoConstants.HDR_L4_SPORT,
                                    ((UdpPortCriterion) criterion).udpPort().toInt(),
                                    ((UdpPortCriterion) criterion).udpPort().toInt())
                                    .build());
                    break;
                case TCP_DST:
                    // TODO: Match a range of TCP port
                    builder.matchPi(
                            PiCriterion.builder().matchRange(
                                    P4InfoConstants.HDR_L4_DPORT,
                                    ((TcpPortCriterion) criterion).tcpPort().toInt(),
                                    ((TcpPortCriterion) criterion).tcpPort().toInt())
                                    .build());
                    break;
                case UDP_DST:
                    // TODO: Match a range of UDP port
                    builder.matchPi(
                            PiCriterion.builder().matchRange(
                                    P4InfoConstants.HDR_L4_DPORT,
                                    ((UdpPortCriterion) criterion).udpPort().toInt(),
                                    ((UdpPortCriterion) criterion).udpPort().toInt())
                                    .build());
                    break;
                default:
                    log.warn("Unsupported criterion type: {}", criterion.type());
            }
        }
        return builder.build();
    }

    /**
     * Returns a subset of Criterion from given selector, which is unsupported by this INT
     * pipeline.
     *
     * @param selector a traffic selector
     * @return a subset of Criterion from given selector, unsupported by this INT pipeline, empty if
     * all criteria are supported.
     */
    private Set<Criterion> unsupportedSelectors(TrafficSelector selector) {
        return selector.criteria().stream()
                .filter(criterion -> !SUPPORTED_CRITERION.contains(criterion.type()))
                .collect(Collectors.toSet());
    }

    private boolean processIntObjective(IntObjective obj, boolean install) {
        if (install && !unsupportedSelectors(obj.selector()).isEmpty()) {
            log.warn("Criteria {} not supported by {} for INT watchlist",
                    unsupportedSelectors(obj.selector()), deviceId);
            return false;
        }

        final FlowRule flowRule = buildCollectorEntry(obj);
        if (flowRule != null) {
            if (install) {
                flowRuleService.applyFlowRules(flowRule);
            } else {
                flowRuleService.removeFlowRules(flowRule);
            }
            log.debug("IntObjective {} has been {} {}",
                    obj, install ? "installed to" : "removed from", deviceId);
            return true;
        } else {
            log.warn("Failed to {} IntObjective {} on {}",
                    install ? "install" : "remove", obj, deviceId);
            return false;
        }
    }

    private boolean setupIntReportInternal(IntDeviceConfig cfg) {
        final FlowRule reportRule = buildReportEntry(cfg);
        if (reportRule != null) {
            flowRuleService.applyFlowRules(reportRule);
            log.info("Report rule added to {} [{}]", this.data().deviceId(), reportRule);
            return true;
        } else {
            log.warn("Failed to add report rule to {}", this.data().deviceId());
            return false;
        }
    }

    private FlowRule buildReportEntry(IntDeviceConfig intCfg) {

        if (!setupBehaviour()) {
            return null;
        }

        final SegmentRoutingDeviceConfig srCfg = cfgService.getConfig(
                deviceId, SegmentRoutingDeviceConfig.class);
        if (srCfg == null) {
            log.error("Missing SegmentRoutingDeviceConfig config for {}, " +
                    "cannot derive source IP for INT reports", deviceId);
            return null;
        }

        final Ip4Address srcIp = srCfg.routerIpv4();
        log.info("For {} overriding sink IPv4 addr ({}) " +
                        "with segmentrouting ipv4Loopback ({}), also ignoring MAC addresses",
                deviceId, intCfg.sinkIp(), srcIp);

        final PiActionParam srcMacParam = new PiActionParam(
                P4InfoConstants.SRC_MAC, MacAddress.ZERO.toBytes());
        final PiActionParam nextHopMacParam = new PiActionParam(
                P4InfoConstants.MON_MAC, MacAddress.ZERO.toBytes());
        final PiActionParam srcIpParam = new PiActionParam(
                P4InfoConstants.SRC_IP, srcIp.toOctets());
        final PiActionParam monIpParam = new PiActionParam(
                P4InfoConstants.MON_IP,
                intCfg.collectorIp().toOctets());
        final PiActionParam monPortParam = new PiActionParam(
                P4InfoConstants.MON_PORT,
                intCfg.collectorPort().toInt());
        final PiAction reportAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_REPORT_ENCAPSULATION)
                .withParameter(srcMacParam)
                .withParameter(nextHopMacParam)
                .withParameter(srcIpParam)
                .withParameter(monIpParam)
                .withParameter(monPortParam)
                .build();
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(reportAction)
                .build();
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder()
                        .matchExact(P4InfoConstants.HDR_INT_MIRROR_VALID, 1)
                        .build())
                .build();
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(this.data().deviceId())
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_REPORT)
                .build();
    }
}
