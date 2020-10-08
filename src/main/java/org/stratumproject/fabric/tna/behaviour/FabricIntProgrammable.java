// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
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
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.stratumproject.fabric.tna.PipeconfLoader;

import java.util.Map;
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

    private static final Map<Integer, Integer> QUAD_PIPE_MIRROR_SESS_TO_RECIRC_PORTS =
            ImmutableMap.<Integer, Integer>builder()
                    .put(300, 0x44)
                    .put(301, 0xc4)
                    .put(302, 0x144)
                    .put(303, 0x1c4).build();

    private static final Map<Integer, Integer> DUAL_PIPE_MIRROR_SESS_TO_RECIRC_PORTS =
            ImmutableMap.<Integer, Integer>builder()
                    .put(300, 0x44)
                    .put(301, 0xc4).build();

    private static final Set<Criterion.Type> SUPPORTED_CRITERION = Sets.newHashSet(
            Criterion.Type.IPV4_DST, Criterion.Type.IPV4_SRC,
            Criterion.Type.UDP_SRC, Criterion.Type.UDP_DST,
            Criterion.Type.TCP_SRC, Criterion.Type.TCP_DST);

    private static final Set<TableId> TABLES_TO_CLEANUP = Sets.newHashSet(
            P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_WATCHLIST,
            P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_REPORT
    );

    private FlowRuleService flowRuleService;
    private GroupService groupService;
    private NetworkConfigService cfgService;
    private HostService hostService;

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
        hostService = handler().get(HostService.class);
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

        final Map<Integer, Integer> sessionToPortMap;
        final var hwPipeCount = capabilities.hwPipeCount();
        switch (hwPipeCount) {
            case 4:
                sessionToPortMap = QUAD_PIPE_MIRROR_SESS_TO_RECIRC_PORTS;
                break;
            case 2:
                sessionToPortMap = DUAL_PIPE_MIRROR_SESS_TO_RECIRC_PORTS;
                break;
            default:
                log.error("{} it not a valid HW pipe count", hwPipeCount);
                return false;
        }

        // Mirroring sessions for report cloning.
        sessionToPortMap.entrySet().stream()
                .map(entry -> {
                    final var sessionId = entry.getKey();
                    final var port = entry.getValue();
                    final var buckets = ImmutableList.of(
                            createCloneGroupBucket(DefaultTrafficTreatment.builder()
                                    .setOutput(PortNumber.portNumber(port))
                                    .build()));
                    return new DefaultGroupDescription(
                            deviceId, GroupDescription.Type.CLONE,
                            new GroupBuckets(buckets),
                            new DefaultGroupKey(KRYO.serialize(sessionId)),
                            sessionId, appId);
                })
                .forEach(groupService::addGroup);

        return true;
    }

    @Override
    public boolean setSourcePort(PortNumber port) {
        return true;
    }

    @Override
    public boolean setSinkPort(PortNumber port) {
        return true;
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
                .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_INIT_METADATA)
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
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_WATCHLIST)
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
        } else {
            log.warn("Failed to add report rule to {}", this.data().deviceId());
            return false;
        }
        final FlowRule quantizeRule = buildQuantizeRule(cfg.minFlowHopLatencyChangeNs());
        flowRuleService.applyFlowRules(quantizeRule);
        log.info("Report rule added to {} [{}]", this.data().deviceId(), quantizeRule);
        return true;
    }

    private FlowRule buildQuantizeRule(int minFlowHopLatencyChangeNs) {
        final long qmask = getSuitableQmaskForLatencyChange(minFlowHopLatencyChangeNs);
        // Quantify hop latency rule
        final PiActionParam quantizeMaskParam = new PiActionParam(P4InfoConstants.QMASK, qmask);
        final PiAction quantizeAction =
                PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_FLOW_REPORT_FILTER_QUANTIZE)
                        .withParameter(quantizeMaskParam)
                        .build();
        final TrafficTreatment quantizeTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(quantizeAction)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .makePermanent()
                .withPriority(DEFAULT_PRIORITY)
                .withTreatment(quantizeTreatment)
                .fromApp(appId)
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_FLOW_REPORT_FILTER_QUANTIZE_HOP_LATENCY)
                .build();
    }

    /**
     * Gets a suitable quantization mask for a minimal latency change.
     * For example, if we want to ignore any latency change that smaller
     * than 256ns, the pipeline will use mask 0xffffff00 which makes
     * any value from 1 to 255 become zero.
     * Note that if the value of latency change is not power of 2 (2^n),
     * this method will find the closest value which is smaller than the value.
     * For example, if we expect to ignore latency change which is smaller than 300ns,
     * the method will use the same mask for 256ns, which is also 0xffffff00.
     *
     * @param minFlowHopLatencyChangeNs the minimal latency change we want to ignore
     * @return the suitable quantization mask
     */
    public long getSuitableQmaskForLatencyChange(int minFlowHopLatencyChangeNs) {
        if (minFlowHopLatencyChangeNs < 0) {
            throw new IllegalArgumentException(
                    "Flow latency change value must equal or greater than zero.");
        }
        long qmask = 0xffffffff;
        while (minFlowHopLatencyChangeNs > 1) {
            minFlowHopLatencyChangeNs /= 2;
            qmask <<= 1;
        }
        return 0xffffffffL & qmask;
    }

    private int getSidForCollector(IpAddress collectorIp) {
        Set<Host> collectorHosts = hostService.getHostsByIp(collectorIp);
        if (collectorHosts.isEmpty()) {
            log.warn("Unable to find collector with IP {}, skip for now.",
                    collectorIp);
            return -1;
        }
        Host collector = collectorHosts.iterator().next();
        if (collectorHosts.size() > 1) {
            log.warn("Find more than one host with IP {}, will use {} as collector.",
                    collectorIp, collector.id());
        }
        Set<HostLocation> locations = collector.locations();
        if (locations.isEmpty()) {
            log.warn("Unable to find the location of collector {}, skip for now.",
                    collector.id());
        }
        HostLocation location = locations.iterator().next();
        if (locations.size() > 1) {
            log.warn("Find more than one location for host {}, will use {}",
                    collector.id(), location);
        }
        DeviceId deviceWithCollector = location.deviceId();
        SegmentRoutingDeviceConfig cfg = cfgService.getConfig(
                deviceWithCollector, SegmentRoutingDeviceConfig.class);
        if (cfg == null) {
            log.error("Missing SegmentRoutingDeviceConfig config for {}, " +
                    "cannot derive SID for collector", deviceWithCollector);
            return -1;
        }
        return cfg.nodeSidIPv4();
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

        // If the device is a spine device, we need to find which
        // switch is the INT collector attached to.
        // And find the SID of that device.
        int sid = -1;
        if (!srCfg.isEdgeRouter()) {
            // TODO: replace this to SR API.
            sid = getSidForCollector(intCfg.collectorIp());
            if (sid == -1) {
                // Error log will be shown in getSidForCollector method.
                return null;
            }
        }

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
        PiAction reportAction;
        if (!srCfg.isEdgeRouter() && sid != -1) {
            final PiActionParam monLabelParam = new PiActionParam(
                    P4InfoConstants.MON_LABEL,
                    sid);
            reportAction = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_REPORT_ENCAP_MPLS)
                    .withParameter(srcMacParam)
                    .withParameter(nextHopMacParam)
                    .withParameter(srcIpParam)
                    .withParameter(monIpParam)
                    .withParameter(monPortParam)
                    .withParameter(monLabelParam)
                    .build();
        } else {
            reportAction = PiAction.builder()
                    .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_REPORT_ENCAP)
                    .withParameter(srcMacParam)
                    .withParameter(nextHopMacParam)
                    .withParameter(srcIpParam)
                    .withParameter(monIpParam)
                    .withParameter(monPortParam)
                    .build();
        }

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
