// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour;

import com.google.common.collect.BoundType;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Range;
import com.google.common.collect.Sets;
import com.google.common.collect.Streams;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.util.HexString;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TableId;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.flow.instructions.PiInstruction;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiMatchFieldModel;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.model.PiTableModel;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.stratumproject.fabric.tna.PipeconfLoader;
import org.stratumproject.fabric.tna.inbandtelemetry.IntProgrammable;
import org.stratumproject.fabric.tna.inbandtelemetry.IntReportConfig;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.StreamSupport;

import static java.lang.String.format;
import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.KRYO;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.doCareRangeMatch;

/**
 * Implementation of INT programmable behavior for fabric.p4.
 */
public class FabricIntProgrammable extends AbstractFabricHandlerBehavior
        implements IntProgrammable {

    private static final int DEFAULT_PRIORITY = 10000;

    // TODO: make configurable at runtime via netcfg
    // By default report every 2^30 ns (~1 second)
    private static final ImmutableByteSequence DEFAULT_TIMESTAMP_MASK =
            ImmutableByteSequence.copyFrom(
                    HexString.fromHexString("ffffc0000000", ""));
    // Default latency threshold for queue report and queue size.
    private static final byte MAX_QUEUES = 32;

    private static final Map<Integer, Integer> QUAD_PIPE_MIRROR_SESS_TO_RECIRC_PORTS =
            ImmutableMap.<Integer, Integer>builder()
                    .put(0x200, 0x44)
                    .put(0x201, 0xc4)
                    .put(0x202, 0x144)
                    .put(0x203, 0x1c4).build();

    private static final Map<Integer, Integer> DUAL_PIPE_MIRROR_SESS_TO_RECIRC_PORTS =
            ImmutableMap.<Integer, Integer>builder()
                    .put(0x200, 0x44)
                    .put(0x201, 0xc4).build();

    private static final Set<TableId> TABLES_TO_CLEANUP = Sets.newHashSet(
            P4InfoConstants.FABRIC_INGRESS_INT_WATCHLIST_WATCHLIST,
            P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_REPORT,
            P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_CONFIG,
            P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_QUEUE_LATENCY_THRESHOLDS
    );
    private static final short BMD_TYPE_EGRESS_MIRROR = 2;
    private static final short BMD_TYPE_INT_INGRESS_DROP = 4;
    private static final short BMD_TYPE_DEFLECTED = 5;
    private static final short MIRROR_TYPE_INVALID = 0;
    private static final short MIRROR_TYPE_INT_REPORT = 1;
    private static final short INT_REPORT_TYPE_LOCAL = 1;
    private static final short INT_REPORT_TYPE_DROP = 2;
    private static final int INT_MIRROR_TRUNCATE_MAX_LEN = 128;

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
     * Create a new instance of this behaviour. Used by the abstract projectable
     * model (i.e., {@link org.onosproject.net.Device#as(Class)}.
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
        final int hwPipeCount = capabilities.hwPipeCount();
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
        sessionToPortMap.forEach((sessionId, port) -> {
            // Set up mirror sessions
            final List<GroupBucket> buckets = ImmutableList.of(
                    createCloneGroupBucket(DefaultTrafficTreatment.builder()
                            .truncate(INT_MIRROR_TRUNCATE_MAX_LEN)
                            .setOutput(PortNumber.portNumber(port))
                            .build()));
            groupService.addGroup(new DefaultGroupDescription(
                    deviceId, GroupDescription.Type.CLONE,
                    new GroupBuckets(buckets),
                    new DefaultGroupKey(KRYO.serialize(sessionId)),
                    sessionId, appId));
        });
        return true;
    }

    @Override
    public boolean setUpIntConfig(IntReportConfig config) {

        if (!setupBehaviour()) {
            return false;
        }
        setUpCollectorFlows(config);
        setUpIntWatchlistRules(config.watchSubnets());
        for (byte queueId = 0; queueId < MAX_QUEUES; queueId++) {
            setUpQueueReportThreshold(
                    queueId,
                    config.queueReportTriggerLatencyThresholdNs(queueId),
                    config.queueReportResetLatencyThresholdNs(queueId));
        }
        return setUpIntReportInternal(config);
    }

    @Override
    public boolean cleanup() {

        if (!setupBehaviour()) {
            return false;
        }

        StreamSupport.stream(flowRuleService.getFlowEntries(
                data().deviceId()).spliterator(), false)
                .filter(f -> TABLES_TO_CLEANUP.contains(f.table()))
                .forEach(flowRuleService::removeFlowRules);

        return true;
        // FIXME: saw issue with clone groups disappearing when inserting.deleting watchlist rules
        // for (final Integer reportSessionId : REPORT_MIRROR_SESSION_ID_LIST) {
        //     final var groupKey = new DefaultGroupKey(
        //             KRYO.serialize(reportSessionId));
        //     groupService.removeGroup(deviceId, groupKey, appId);
        // }
    }

    private FlowRule buildWatchlistEntry(TrafficSelector trafficSelector) {
        final PiAction watchlistAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_INT_WATCHLIST_MARK_TO_REPORT)
                .build();
        final TrafficTreatment watchlistTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(watchlistAction)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(trafficSelector)
                .withTreatment(watchlistTreatment)
                .withPriority(DEFAULT_PRIORITY)
                .forTable(P4InfoConstants.FABRIC_INGRESS_INT_WATCHLIST_WATCHLIST)
                .fromApp(appId)
                .makePermanent()
                .build();
    }

    private TrafficSelector buildCollectorSelector(Set<Criterion> criteria) {
        TrafficSelector.Builder builder = DefaultTrafficSelector.builder();
        // We always match packets with valid IPv4 header
        PiCriterion.Builder piBuilder = PiCriterion.builder().matchExact(P4InfoConstants.HDR_IPV4_VALID, 1);
        for (Criterion criterion : criteria) {
            switch (criterion.type()) {
                case IP_PROTO:
                    builder.matchIPProtocol((byte) ((IPProtocolCriterion) criterion).protocol());
                    break;
                case IPV4_SRC:
                    builder.matchIPSrc(((IPCriterion) criterion).ip());
                    break;
                case IPV4_DST:
                    builder.matchIPDst(((IPCriterion) criterion).ip());
                    break;
                case TCP_SRC:
                    // TODO: Match a range of TCP port
                    piBuilder.matchRange(P4InfoConstants.HDR_L4_SPORT,
                            ((TcpPortCriterion) criterion).tcpPort().toInt(),
                            ((TcpPortCriterion) criterion).tcpPort().toInt());
                    break;
                case UDP_SRC:
                    // TODO: Match a range of UDP port
                    piBuilder.matchRange(P4InfoConstants.HDR_L4_SPORT,
                            ((UdpPortCriterion) criterion).udpPort().toInt(),
                            ((UdpPortCriterion) criterion).udpPort().toInt());
                    break;
                case TCP_DST:
                    // TODO: Match a range of TCP port
                    piBuilder.matchRange(P4InfoConstants.HDR_L4_DPORT,
                            ((TcpPortCriterion) criterion).tcpPort().toInt(),
                            ((TcpPortCriterion) criterion).tcpPort().toInt());
                    break;
                case UDP_DST:
                    // TODO: Match a range of UDP port
                    piBuilder.matchRange(P4InfoConstants.HDR_L4_DPORT,
                            ((UdpPortCriterion) criterion).udpPort().toInt(),
                            ((UdpPortCriterion) criterion).udpPort().toInt());
                    break;
                default:
                    log.warn("Unsupported criterion type: {}", criterion.type());
            }
        }
        return builder.matchPi(piBuilder.build()).build();
    }

    private boolean setUpIntReportInternal(IntReportConfig cfg) {
        final List<FlowRule> reportRules = buildReportEntries(cfg);
        if (!reportRules.isEmpty() && reportRules.stream().noneMatch(Objects::isNull)) {
            reportRules.forEach(reportRule -> {
                flowRuleService.applyFlowRules(reportRule);
                log.info("Report rule added to {} [{}]", deviceId, reportRule);
            });
        } else {
            log.warn("Failed to add report rule to {}", deviceId);
            return false;
        }
        final FlowRule filterConfigRule = buildFilterConfigRule(cfg.minFlowHopLatencyChangeNs());
        flowRuleService.applyFlowRules(filterConfigRule);
        log.info("Report rule added to {} [{}]", deviceId, filterConfigRule);
        return true;
    }

    private FlowRule buildFilterConfigRule(int minFlowHopLatencyChangeNs) {
        final long qmask = getSuitableQmaskForLatencyChange(minFlowHopLatencyChangeNs);
        final PiActionParam hopLatencyMask = new PiActionParam(P4InfoConstants.HOP_LATENCY_MASK, qmask);
        final PiActionParam timestampMask = new PiActionParam(P4InfoConstants.TIMESTAMP_MASK, DEFAULT_TIMESTAMP_MASK);
        final PiAction action =
                PiAction.builder()
                        .withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_SET_CONFIG)
                        .withParameter(hopLatencyMask)
                        .withParameter(timestampMask)
                        .build();
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(action)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .makePermanent()
                .withPriority(DEFAULT_PRIORITY)
                .withTreatment(treatment)
                .fromApp(appId)
                .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_CONFIG)
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

    /**
     * Gets the SID of the device which collector attached to.
     * TODO: remove this method once we get SR API done.
     *
     * @param collectorIp the IP address of the INT collector
     * @return the SID of the device, Optional.empty() if we cannot find the SID of
     *         the device
     */
    private Optional<Integer> getSidForCollector(IpAddress collectorIp) {
        Set<Host> collectorHosts = hostService.getHostsByIp(collectorIp);
        if (collectorHosts.isEmpty()) {
            log.warn("Unable to find collector with IP {}, skip for now.", collectorIp);
            return Optional.empty();
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
            return Optional.empty();
        }
        HostLocation location = locations.iterator().next();
        if (locations.size() > 1) {
            // TODO: revisit this when we want to support dual-homed INT collector.
            log.warn("Find more than one location for host {}, will use {}",
                    collector.id(), location);
        }
        DeviceId deviceWithCollector = location.deviceId();
        SegmentRoutingDeviceConfig cfg = cfgService.getConfig(
                deviceWithCollector, SegmentRoutingDeviceConfig.class);
        if (cfg == null) {
            log.error("Missing SegmentRoutingDeviceConfig config for {}, " +
                    "cannot derive SID for collector", deviceWithCollector);
            return Optional.empty();
        }
        if (cfg.nodeSidIPv4() == -1) {
            log.error("Missing ipv4NodeSid in segment routing config for device {}",
                    deviceWithCollector);
            return Optional.empty();
        }
        return Optional.of(cfg.nodeSidIPv4());
    }

    private FlowRule buildReportEntryWithType(SegmentRoutingDeviceConfig srCfg,
            IntReportConfig intCfg, short bridgedMdType, short reportType, short mirrorType) {
        final Ip4Address srcIp = srCfg.routerIpv4();
        final int switchId = srCfg.nodeSidIPv4();

        if (srcIp == null) {
            log.warn("Invalid switch IP, skip configuring the report table");
            return null;
        }

        final PiActionParam srcIpParam = new PiActionParam(
                P4InfoConstants.SRC_IP, srcIp.toOctets());
        final PiActionParam monIpParam = new PiActionParam(
                P4InfoConstants.MON_IP,
                intCfg.collectorIp().toOctets());
        final PiActionParam monPortParam = new PiActionParam(
                P4InfoConstants.MON_PORT,
                intCfg.collectorPort().toInt());
        final PiActionParam switchIdParam = new PiActionParam(
                P4InfoConstants.SWITCH_ID,
                switchId);

        PiAction.Builder reportActionBuilder = PiAction.builder();
        if (!srCfg.isEdgeRouter()) {
            // If the device is a spine device, we need to find which
            // switch is the INT collector attached to and find the SID of that device.
            // TODO: replace this with SR API.
            Optional<Integer> sid = getSidForCollector(intCfg.collectorIp());
            if (sid.isEmpty()) {
                // Error log will be shown in getSidForCollector method.
                return null;
            }

            if (reportType == INT_REPORT_TYPE_LOCAL) {
                reportActionBuilder.withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_LOCAL_REPORT_ENCAP_MPLS);
            } else if (reportType == INT_REPORT_TYPE_DROP) {
                reportActionBuilder.withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_DROP_REPORT_ENCAP_MPLS);
            } else {
                // Invalid report type
                log.warn("Invalid report type {}", reportType);
                return null;
            }

            final PiActionParam monLabelParam = new PiActionParam(
                    P4InfoConstants.MON_LABEL,
                    sid.get());
            reportActionBuilder.withParameter(monLabelParam);
        } else {
            if (reportType == INT_REPORT_TYPE_LOCAL) {
                reportActionBuilder.withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_LOCAL_REPORT_ENCAP);
            } else if (reportType == INT_REPORT_TYPE_DROP) {
                reportActionBuilder.withId(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_DO_DROP_REPORT_ENCAP);
            } else {
                // Invalid report type
                log.warn("Invalid report type {}", reportType);
                return null;
            }
        }

        reportActionBuilder.withParameter(srcIpParam)
                .withParameter(monIpParam)
                .withParameter(monPortParam)
                .withParameter(switchIdParam);
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(reportActionBuilder.build())
                .build();
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder()
                        .matchExact(P4InfoConstants.HDR_BMD_TYPE,
                                bridgedMdType)
                        .matchExact(P4InfoConstants.HDR_MIRROR_TYPE,
                                mirrorType)
                        .matchExact(P4InfoConstants.HDR_INT_REPORT_TYPE,
                                reportType)
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

    private List<FlowRule> buildReportEntries(IntReportConfig intCfg) {
        final SegmentRoutingDeviceConfig srCfg = cfgService.getConfig(
                deviceId, SegmentRoutingDeviceConfig.class);
        if (srCfg == null) {
            log.error("Missing SegmentRoutingDeviceConfig config for {}, " +
                    "cannot derive source IP for INT reports", deviceId);
            return Collections.emptyList();
        }
        return Lists.newArrayList(
                buildReportEntryWithType(srCfg, intCfg, BMD_TYPE_INT_INGRESS_DROP,
                                         INT_REPORT_TYPE_DROP, MIRROR_TYPE_INVALID),
                buildReportEntryWithType(srCfg, intCfg, BMD_TYPE_EGRESS_MIRROR,
                                         INT_REPORT_TYPE_DROP, MIRROR_TYPE_INT_REPORT),
                buildReportEntryWithType(srCfg, intCfg, BMD_TYPE_EGRESS_MIRROR,
                                         INT_REPORT_TYPE_LOCAL, MIRROR_TYPE_INT_REPORT),
                buildReportEntryWithType(srCfg, intCfg, BMD_TYPE_DEFLECTED,
                                         INT_REPORT_TYPE_DROP, MIRROR_TYPE_INVALID)
        );
    }

    private boolean entryWithActionId(FlowEntry flowEntry, PiActionId actionId) {
        return flowEntry.treatment().allInstructions().stream()
                .filter(inst -> inst instanceof PiInstruction)
                .map(inst -> (PiInstruction) inst)
                .map(PiInstruction::action)
                .filter(action -> action instanceof PiAction)
                .map(action -> (PiAction) action)
                .anyMatch(action -> action.id().equals(actionId));
    }

    private void setUpCollectorFlows(IntReportConfig config) {
        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        final PiAction watchlistAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_INT_WATCHLIST_NO_REPORT_COLLECTOR).build();
        Streams.stream(flowRuleService.getFlowEntriesById(appId))
                .filter(entry -> entry.deviceId().equals(deviceId))
                .filter(entry -> entryWithActionId(entry, watchlistAction.id()))
                .forEach(ops::remove);

        ops.newStage();
        final TrafficTreatment watchlistTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(watchlistAction)
                .build();
        final TrafficSelector watchlistSelector = DefaultTrafficSelector.builder()
                        .matchIPDst(config.collectorIp().toIpPrefix())
                        .matchIPProtocol(IPv4.PROTOCOL_UDP)
                        .matchUdpDst(config.collectorPort())
                        .build();

        final FlowRule watchlistRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(buildCollectorSelector(watchlistSelector.criteria()))
                .withTreatment(watchlistTreatment)
                .withPriority(DEFAULT_PRIORITY + 10)
                .forTable(P4InfoConstants.FABRIC_INGRESS_INT_WATCHLIST_WATCHLIST)
                .fromApp(appId)
                .makePermanent()
                .build();
        ops.add(watchlistRule);
        flowRuleService.apply(ops.build());
    }

    /**
     * Get ranges matching values above the given threshold.
     *
     * @param threshold the threshold
     * @return the match ranges, empty if threshold is maximum value of 32-bit unsigned integer
     */
    protected List<List<Range<Integer>>> getMatchRangesForTrigger(long threshold) {
        List<List<Range<Integer>>> result = Lists.newArrayList();
        if (threshold <= 0xffff) {
            // [threshold, 0x0000ffff]
            result.add(ImmutableList.of(Range.closed(0, 0), Range.closed((int) threshold, 0xffff)));
            // [0x00010000, 0xffffffff]
            result.add(ImmutableList.of(Range.closed(1, 0xffff), Range.closed(0, 0xffff)));
        } else if (threshold < 0xffffffffL) {
            int thresholdUpper = (int) (threshold >> 16);
            int thresholdLower = (int) (threshold & 0xffff);
            // [threshold, 0xTTTTffff], "TTTT" is the upper 16-bit of the threshold.
            result.add(ImmutableList.of(
                Range.closed(thresholdUpper, thresholdUpper), Range.closed(thresholdLower, 0xffff)));
            if (thresholdUpper < 0xffff) {
                // [0xTTTTffff, 0xffffffff], "TTTT" is the upper 16-bit of the threshold.
                result.add(ImmutableList.of(Range.closed(thresholdUpper + 1, 0xffff), Range.closed(0, 0xffff)));
            }
        }
        return result;
    }

    /**
     * Get ranges matching values below the given threshold.
     *
     * @param threshold the threshold
     * @return the ranges, or empty list if the threshold is 0
     */
    protected List<List<Range<Integer>>> getMatchRangesForReset(long threshold) {
        List<List<Range<Integer>>> result = Lists.newArrayList();
        int thresholdUpper = (int) (threshold >> 16);
        int thresholdLower = (int) (threshold & 0xffff);
        if (threshold > 0xffff) {
            // [0, 0xTTTT0000), "TTTT" is the upper 16-bit of the threshold.
            result.add(ImmutableList.of(Range.closed(0, thresholdUpper - 1), Range.closed(0, 0xffff)));
            // [0xTTTT0000, threshold), "TTTT" is the upper 16-bit of the threshold.
            result.add(ImmutableList.of(
                Range.closed(thresholdUpper, thresholdUpper), Range.closed(0, thresholdLower - 1)));
        } else if (threshold > 0) {
            // [0, threshold)
            result.add(ImmutableList.of(Range.closed(0, 0), Range.closed(0, thresholdLower - 1)));
        }
        return result;
    }

    private Integer[] rangeToIntArray(Range<Integer> range) {
        Integer[] result = new Integer[] {
            range.lowerEndpoint(),
            range.upperEndpoint()
        };
        // Shift one if it the endpoint bound type is open.
        if (range.lowerBoundType() == BoundType.OPEN) {
            result[0]++;
        }
        if (range.upperBoundType() == BoundType.OPEN) {
            result[1]--;
        }
        return result;
    }

    protected int getFieldSize(PiTableId piTableId, PiMatchFieldId piMatchFieldId) {
        PiTableModel piTableModel = pipeconf.pipelineModel().table(piTableId).orElse(null);
        if (piTableModel == null) {
            throw new IllegalArgumentException(format("Pipeline does not have %s table", piTableId));
        }
        PiMatchFieldModel piMatchFieldModel = piTableModel.matchField(piMatchFieldId)
                .orElse(null);
        if (piMatchFieldModel == null) {
            throw new IllegalArgumentException(format("Pipeline does not have %s field match", piMatchFieldId));
        }
        return piMatchFieldModel.bitWidth();
    }

    private void setUpQueueReportThresholdInternal(byte queueId, Range<Integer> upperRange,
            Range<Integer> lowerRange, PiActionId actionId) {
        Integer[] thresholdUpper = rangeToIntArray(upperRange);
        Integer[] thresholdLower = rangeToIntArray(lowerRange);
        final PiCriterion.Builder matchCriterionBuilder = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_EGRESS_QID, queueId);
        int bitWidth = getFieldSize(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_QUEUE_LATENCY_THRESHOLDS,
                P4InfoConstants.HDR_HOP_LATENCY_UPPER);
        if (doCareRangeMatch(thresholdUpper[0], thresholdUpper[1], bitWidth)) {
                matchCriterionBuilder.matchRange(P4InfoConstants.HDR_HOP_LATENCY_UPPER, thresholdUpper[0],
                        thresholdUpper[1]);
        }
        bitWidth = getFieldSize(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_QUEUE_LATENCY_THRESHOLDS,
                P4InfoConstants.HDR_HOP_LATENCY_LOWER);
        if (doCareRangeMatch(thresholdLower[0], thresholdLower[1], bitWidth)) {
                matchCriterionBuilder.matchRange(P4InfoConstants.HDR_HOP_LATENCY_LOWER, thresholdLower[0],
                        thresholdLower[1]);
        }
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(matchCriterionBuilder.build())
                .build();
        final TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(PiAction.builder().withId(actionId).build())
                .build();
        final FlowRule queueReportFlow = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .forTable(P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_QUEUE_LATENCY_THRESHOLDS)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .withPriority(DEFAULT_PRIORITY)
            .build();
        flowRuleService.applyFlowRules(queueReportFlow);
    }

    private void setUpQueueReportThreshold(byte queueId, long thresholdToTrigger,
        long thresholdToReset) {
        // Latency values higher than this threshold, should trigger a quota check and report generation.
        for (List<Range<Integer>> ranges : getMatchRangesForTrigger(thresholdToTrigger)) {
            setUpQueueReportThresholdInternal(queueId, ranges.get(0), ranges.get(1),
                    P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_CHECK_QUOTA);
        }
        // Latency values lower than the threshold, resets the queue report quota.
        for (List<Range<Integer>> ranges : getMatchRangesForReset(thresholdToReset)) {
            setUpQueueReportThresholdInternal(queueId, ranges.get(0), ranges.get(1),
                    P4InfoConstants.FABRIC_EGRESS_INT_EGRESS_RESET_QUOTA);
        }
    }

    private void setUpIntWatchlistRules(List<IpPrefix> watchSubnets) {
        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        final PiActionId reportActionId = P4InfoConstants.FABRIC_INGRESS_INT_WATCHLIST_MARK_TO_REPORT;
        Streams.stream(flowRuleService.getFlowEntriesById(appId))
                .filter(entry -> entry.deviceId().equals(deviceId))
                .filter(entry -> entryWithActionId(entry, reportActionId))
                .forEach(ops::remove);
        ops.newStage();
        for (IpPrefix subnet : watchSubnets) {
            if (subnet.prefixLength() == 0) {
                ops.add(buildWatchlistEntry(buildCollectorSelector(Collections.emptySet())));
                continue;
            }
            ops.add(buildWatchlistEntry(buildCollectorSelector(ImmutableSet.of(Criteria.matchIPSrc(subnet)))));
            ops.add(buildWatchlistEntry(buildCollectorSelector(ImmutableSet.of(Criteria.matchIPDst(subnet)))));
        }

        flowRuleService.apply(ops.build());
    }
}
