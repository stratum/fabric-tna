// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.Ip4Prefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.drivers.p4runtime.AbstractP4RuntimeHandlerBehaviour;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.upf.*;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.model.PiTableModel;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiCounterCell;
import org.onosproject.net.pi.runtime.PiCounterCellHandle;
import org.onosproject.net.pi.runtime.PiCounterCellId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.PipeconfLoader;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.onosproject.net.pi.model.PiCounterType.INDIRECT;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.*;

/**
 * Implementation of a UPF programmable device behavior.
 */
public class FabricUpfProgrammable extends AbstractP4RuntimeHandlerBehaviour
        implements UpfProgrammable {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private static final int DEFAULT_PRIORITY = 128;
    private static final long DEFAULT_P4_DEVICE_ID = 1;

    private static final int PRIORITY_LOW = 10;

    protected FlowRuleService flowRuleService;
    protected SlicingService slicingService;
    protected PacketService packetService;
    protected FabricUpfTranslator upfTranslator;

    private long uplinkUeSessionsTableSize;
    private long downlinkUeSessionsTableSize;
    private long uplinkUpfTerminationsTableSize;
    private long downlinkUpfTerminationsTableSize;
    private long pdrCounterSize;

    private ApplicationId appId;

    @Override
    protected boolean setupBehaviour(String opName) {
        // Already initialized.
        if (appId != null) {
            return true;
        }

        if (!super.setupBehaviour(opName)) {
            return false;
        }

        if (!computeHardwareResourceSizes()) {
            // error message will be printed by computeHardwareResourceSizes()
            return false;
        }

        flowRuleService = handler().get(FlowRuleService.class);
        slicingService = handler().get(SlicingService.class);
        packetService = handler().get(PacketService.class);
        upfTranslator = new FabricUpfTranslator();
        final CoreService coreService = handler().get(CoreService.class);
        appId = coreService.getAppId(PipeconfLoader.APP_NAME_UPF);
        if (appId == null) {
            log.warn("Application ID is null. Cannot initialize behaviour.");
            return false;
        }

        var capabilities = new FabricCapabilities(pipeconf);
        if (!capabilities.supportUpf()) {
            log.warn("Pipeconf {} on {} does not support UPF capabilities, " +
                             "cannot perform {}",
                     pipeconf.id(), deviceId, opName);
            return false;
        }
        return true;
    }

    @Override
    public boolean init() {
        if (setupBehaviour("init()")) {
            log.info("UpfProgrammable initialized for appId {} and deviceId {}", appId, deviceId);
            // Add static Queue Configuration
            // Default slice and best effort TC will be created by SlicingService by default
            slicingService.addTrafficClass(SliceId.DEFAULT, TrafficClass.CONTROL);
            slicingService.addTrafficClass(SliceId.DEFAULT, TrafficClass.REAL_TIME);
            slicingService.addTrafficClass(SliceId.DEFAULT, TrafficClass.ELASTIC);
            return true;
        }
        return false;
    }

    private FlowRule setQueueFlowRule(int sliceId, int tc, int queueId) {
        TrafficSelector trafficSelector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder().matchExact(HDR_SLICE_TC, sliceTcConcat(sliceId, tc)).build())
                .build();
        PiAction action = PiAction.builder()
                .withId(FABRIC_INGRESS_QOS_SET_QUEUE)
                .withParameter(new PiActionParam(QID, queueId))
                .build();

        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(FABRIC_INGRESS_QOS_QUEUES)
                .withSelector(trafficSelector)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(PRIORITY_LOW)
                .build();
    }

    @Override
    public boolean fromThisUpf(FlowRule flowRule) {
        return flowRule.deviceId().equals(this.deviceId) &&
                flowRule.appId() == appId.id();
    }

    /**
     * Grab the capacities for the UE Sessions and UPF Terminations tables from the pipeconf.
     * Runs only once, on initialization.
     *
     * @return true if resource is fetched successfully, false otherwise.
     * @throws IllegalStateException when UE Sessions or UPF Terminations table can't be found in the pipeline model.
     */
    private boolean computeHardwareResourceSizes() {
        long uplinkUeSessionsTableSize = 0;
        long downlinkUeSessionsTableSize = 0;
        long uplinkUpfTerminationsTableSize = 0;
        long downlinkUpfTerminationsTableSize = 0;

        // Get table sizes of interest
        for (PiTableModel piTable : pipeconf.pipelineModel().tables()) {
            if (piTable.id().equals(FABRIC_INGRESS_SPGW_UPLINK_SESSIONS)) {
                uplinkUeSessionsTableSize = piTable.maxSize();
            } else if (piTable.id().equals(FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS)) {
                downlinkUeSessionsTableSize = piTable.maxSize();
            } else if (piTable.id().equals(FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS)) {
                uplinkUpfTerminationsTableSize = piTable.maxSize();
            } else if (piTable.id().equals(FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS)) {
                downlinkUpfTerminationsTableSize = piTable.maxSize();
            }
        }
        if (uplinkUeSessionsTableSize == 0) {
            throw new IllegalStateException("Unable to find uplink UE Sessions table in pipeline model.");
        }
        if (downlinkUeSessionsTableSize == 0) {
            throw new IllegalStateException("Unable to find downlink UE Sessions table in pipeline model.");
        }
        if (uplinkUpfTerminationsTableSize == 0) {
            throw new IllegalStateException("Unable to find uplink UPF Terminations table in pipeline model.");
        }
        if (downlinkUpfTerminationsTableSize == 0) {
            throw new IllegalStateException("Unable to find downlink UPF Terminations table in pipeline model.");
        }

        // Get counter sizes of interest
        long ingressCounterSize = 0;
        long egressCounterSize = 0;
        for (PiCounterModel piCounter : pipeconf.pipelineModel().counters()) {
            if (piCounter.id().equals(FABRIC_INGRESS_SPGW_PDR_COUNTER)) {
                ingressCounterSize = piCounter.size();
            } else if (piCounter.id().equals(FABRIC_EGRESS_SPGW_PDR_COUNTER)) {
                egressCounterSize = piCounter.size();
            }
        }
        if (ingressCounterSize != egressCounterSize) {
            log.warn("PDR ingress and egress counter sizes are not equal! Using the minimum of the two.");
        }

        this.uplinkUeSessionsTableSize = uplinkUeSessionsTableSize;
        this.downlinkUeSessionsTableSize = downlinkUeSessionsTableSize;
        this.uplinkUpfTerminationsTableSize = uplinkUpfTerminationsTableSize;
        this.downlinkUpfTerminationsTableSize = downlinkUpfTerminationsTableSize;
        this.pdrCounterSize = Math.min(ingressCounterSize, egressCounterSize);

        return true;
    }

    @Override
    public void enablePscEncap() {
        if (!setupBehaviour("enablePscEncap()")) {
            return;
        }
        if (pipeconf.pipelineModel().table(FABRIC_EGRESS_SPGW_GTPU_ENCAP).isEmpty()) {
            log.error("Missing {} table in {}, cannot enable PSC encap",
                      FABRIC_EGRESS_SPGW_GTPU_ENCAP, deviceId);
            return;
        }
        flowRuleService.applyFlowRules(upfTranslator.buildGtpuWithPscEncapRule(
                deviceId, appId));
    }

    @Override
    public void disablePscEncap() {
        if (!setupBehaviour("disablePscEncap()")) {
            return;
        }
        if (pipeconf.pipelineModel().table(FABRIC_EGRESS_SPGW_GTPU_ENCAP).isEmpty()) {
            log.debug("Missing {} table in {}, assuming PSC encap is disabled by default",
                      FABRIC_EGRESS_SPGW_GTPU_ENCAP, deviceId);
            return;
        }
        flowRuleService.applyFlowRules(upfTranslator.buildGtpuOnlyEncapRule(
                deviceId, appId));
    }

    @Override
    public void sendPacketOut(ByteBuffer data) {
        if (!setupBehaviour("sendPacketOut()")) {
            return;
        }
        final OutboundPacket pkt = new DefaultOutboundPacket(
                deviceId,
                // Use TABLE logical port to have pkt routed via pipeline tables.
                DefaultTrafficTreatment.builder()
                        .setOutput(PortNumber.TABLE)
                        .build(),
                data);
        packetService.emit(pkt);
    }

    @Override
    public void cleanUp() {
        if (!setupBehaviour("cleanUp()")) {
            return;
        }
        log.info("Clearing all UPF-related table entries.");
        // Remove static Queue Configuration
        slicingService.removeTrafficClass(SliceId.DEFAULT, TrafficClass.CONTROL);
        slicingService.removeTrafficClass(SliceId.DEFAULT, TrafficClass.REAL_TIME);
        slicingService.removeTrafficClass(SliceId.DEFAULT, TrafficClass.ELASTIC);
    }

    @Override
    public void clearInterfaces() {
        if (!setupBehaviour("clearInterfaces()")) {
            return;
        }
        log.info("Clearing all UPF interfaces.");
        for (FlowRule entry : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricInterface(entry)) {
                try {
                    var iface = upfTranslator.fabricEntryToInterface(entry);
                    if (iface.isCore()) {
                        applyUplinkRecirculation(iface.prefix(), true);
                    }
                } catch (UpfProgrammableException e) {
                    log.error("Error when translating interface entry, " +
                            "will skip removing uplink recirculation rules: {} [{}]", e.getMessage(), entry);
                }
                flowRuleService.removeFlowRules(entry);
            }
        }
    }

    @Override
    public void clearFlows() {
        if (!setupBehaviour("clearFlows()")) {
            return;
        }
        log.info("Clearing all UE sessions and UPF Terminations.");
        int ueSessionsCleared = 0;
        int upfTerminationsCleared = 0;
        for (FlowRule entry : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricUeSessionRule(entry)) {
                ueSessionsCleared++;
                flowRuleService.removeFlowRules(entry);
            } else if (upfTranslator.isFabricUpfTerminationRule(entry)) {
                upfTerminationsCleared++;
                flowRuleService.removeFlowRules(entry);
            }
        }
        log.info("Cleared {} UE sessions and {} UPF Terminations.", ueSessionsCleared, upfTerminationsCleared);
    }

    @Override
    public Collection<GtpTunnelPeer> getGtpTunnelPeers() throws UpfProgrammableException {
        if (!setupBehaviour("getGtpTunnelPeers()")) {
            return null;
        }

        ArrayList<GtpTunnelPeer> gtpTunnelPeers = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricGtpTunnelPeer(flowRule)) {
                gtpTunnelPeers.add(upfTranslator.fabricEntryToGtpTunnelPeer(flowRule));
            }
        }
        return gtpTunnelPeers;
    }

    @Override
    public Collection<UeSession> getUeSessions() throws UpfProgrammableException {
        if (!setupBehaviour("getUeSessions()")) {
            return null;
        }

        ArrayList<UeSession> ueSessions = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricUeSessionRule(flowRule)) {
                ueSessions.add(upfTranslator.fabricEntryToUeSession(flowRule));
            }
        }
        return ueSessions;
    }

    @Override
    public Collection<UpfTerminationRule> getUpfTerminationRules() throws UpfProgrammableException {
        if (!setupBehaviour("getUpfTerminationRules()")) {
            return null;
        }

        ArrayList<UpfTerminationRule> upfTerminationRules = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricUpfTerminationRule(flowRule)) {
                upfTerminationRules.add(upfTranslator.fabricEntryToUpfTerminationRule(flowRule));
            }
        }

        return upfTerminationRules;
    }


    @Override
    public Collection<PdrStats> readAllCounters(long maxCounterId) {
        if (!setupBehaviour("readAllCounters()")) {
            return null;
        }

        long counterSize = pdrCounterSize();
        if (maxCounterId != -1) {
            counterSize = Math.min(maxCounterId, counterSize);
        }

        // Prepare PdrStats object builders, one for each counter ID currently in use
        Map<Integer, PdrStats.Builder> pdrStatBuilders = Maps.newHashMap();
        for (int cellId = 0; cellId < counterSize; cellId++) {
            pdrStatBuilders.put(cellId, PdrStats.builder().withCellId(cellId));
        }

        // Generate the counter cell IDs.
        Set<PiCounterId> counterIds = ImmutableSet.of(
                FABRIC_INGRESS_SPGW_PDR_COUNTER,
                FABRIC_EGRESS_SPGW_PDR_COUNTER
        );

        // Query the device.
        Collection<PiCounterCell> counterEntryResponse = client.read(
                DEFAULT_P4_DEVICE_ID, pipeconf)
                .counterCells(counterIds)
                .submitSync()
                .all(PiCounterCell.class);

        // Process response.
        counterEntryResponse.forEach(counterCell -> {
            if (counterCell.cellId().counterType() != INDIRECT) {
                log.warn("Invalid counter data type {}, skipping", counterCell.cellId().counterType());
                return;
            }
            if (!pdrStatBuilders.containsKey((int) counterCell.cellId().index())) {
                // Most likely Up4config.maxUes() is set to a value smaller than what the switch
                // pipeline can hold.
                log.debug("Unrecognized index {} when reading all counters, " +
                        "that's expected if we are manually limiting maxUes", counterCell);
                return;
            }
            PdrStats.Builder statsBuilder = pdrStatBuilders.get((int) counterCell.cellId().index());
            if (counterCell.cellId().counterId().equals(FABRIC_INGRESS_SPGW_PDR_COUNTER)) {
                statsBuilder.setIngress(counterCell.data().packets(),
                        counterCell.data().bytes());
            } else if (counterCell.cellId().counterId().equals(FABRIC_EGRESS_SPGW_PDR_COUNTER)) {
                statsBuilder.setEgress(counterCell.data().packets(),
                        counterCell.data().bytes());
            } else {
                log.warn("Unrecognized counter ID {}, skipping", counterCell);
            }
        });

        return pdrStatBuilders
                .values()
                .stream()
                .map(PdrStats.Builder::build)
                .collect(Collectors.toList());
    }

    @Override
    public long gtpTunnelPeersTableSize() {
        if (!setupBehaviour("gtpTunnelPeersTableSize()")) {
            return -1;
        }
        // TODO: return gtpTunnelPeersTableSize
        return 0;
    }

    @Override
    public long ueSessionTableSize() {
        if (!setupBehaviour("ueSessionTableSize()")) {
            return -1;
        }
        // TODO: the size of uplink UE Session table is greater than downlink as we might have multiple TEIDs per UE
        //  decide what to return as ueSessionTableSize
        return Math.min(this.uplinkUeSessionsTableSize, this.downlinkUeSessionsTableSize);
    }

    @Override
    public long upfTerminationTableSize() {
        if (!setupBehaviour("upfTerminationTableSize()")) {
            return -1;
        }

        // use min, but the size of uplink and downlink tables should be equal.
        return Math.min(this.uplinkUpfTerminationsTableSize, this.downlinkUpfTerminationsTableSize);
    }

    @Override
    public long pdrCounterSize() {
        if (!setupBehaviour("pdrCounterSize()")) {
            return -1;
        }
        return pdrCounterSize;
    }

    @Override
    public PdrStats readCounter(int cellId) throws UpfProgrammableException {
        if (!setupBehaviour("readCounter()")) {
            return null;
        }
        if (cellId >= pdrCounterSize() || cellId < 0) {
            throw new UpfProgrammableException("Requested PDR counter cell index is out of bounds.",
                    UpfProgrammableException.Type.COUNTER_INDEX_OUT_OF_RANGE);
        }
        PdrStats.Builder stats = PdrStats.builder().withCellId(cellId);

        // Make list of cell handles we want to read.
        List<PiCounterCellHandle> counterCellHandles = List.of(
                PiCounterCellHandle.of(deviceId,
                        PiCounterCellId.ofIndirect(FABRIC_INGRESS_SPGW_PDR_COUNTER, cellId)),
                PiCounterCellHandle.of(deviceId,
                        PiCounterCellId.ofIndirect(FABRIC_EGRESS_SPGW_PDR_COUNTER, cellId)));

        // Query the device.
        Collection<PiCounterCell> counterEntryResponse = client.read(
                DEFAULT_P4_DEVICE_ID, pipeconf)
                .handles(counterCellHandles).submitSync()
                .all(PiCounterCell.class);

        // Process response.
        counterEntryResponse.forEach(counterCell -> {
            if (counterCell.cellId().counterType() != INDIRECT) {
                log.warn("Invalid counter data type {}, skipping", counterCell.cellId().counterType());
                return;
            }
            if (cellId != counterCell.cellId().index()) {
                log.warn("Unrecognized counter index {}, skipping", counterCell);
                return;
            }
            if (counterCell.cellId().counterId().equals(FABRIC_INGRESS_SPGW_PDR_COUNTER)) {
                stats.setIngress(counterCell.data().packets(), counterCell.data().bytes());
            } else if (counterCell.cellId().counterId().equals(FABRIC_EGRESS_SPGW_PDR_COUNTER)) {
                stats.setEgress(counterCell.data().packets(), counterCell.data().bytes());
            } else {
                log.warn("Unrecognized counter ID {}, skipping", counterCell);
            }
        });
        return stats.build();
    }

    @Override
    public void addInterface(UpfInterface upfInterface) throws UpfProgrammableException {
        if (!setupBehaviour("addInterface()")) {
            return;
        }
        FlowRule flowRule = upfTranslator.interfaceToFabricEntry(upfInterface, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", upfInterface);
        flowRuleService.applyFlowRules(flowRule);
        log.debug("Interface added with flowID {}", flowRule.id().value());
        // By default we enable UE-to-UE communication on the UE subnet identified by the CORE interface.
        // TODO: allow enabling/disabling UE-to-UE via netcfg or other API.
        if (upfInterface.isCore()) {
            applyUplinkRecirculation(upfInterface.prefix(), false);
        }
    }

    private boolean removeEntry(PiCriterion match, PiTableId tableId, boolean failSilent)
            throws UpfProgrammableException {
        FlowRule entry = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(tableId)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withPriority(DEFAULT_PRIORITY)
                .build();

        try {
            flowRuleService.removeFlowRules(entry);
            // TODO in future we may need to send other notifications to the pfcp agent
            //if (!failSilent) {
            //    throw new UpfProgrammableException("Match criterion " + match.toString() +
            //            " not found in table " + tableId.toString());
            //}
            return true;
        } catch (Exception e) {
            log.error("Exception thrown while removing flows", e);
        }
        // Assumes that the ONOS state is ok and the pfcp agent
        // is not asking to remove wrong flows
        if (!failSilent) {
            throw new UpfProgrammableException("Unable to remove FlowRule with match criterion " + match.toString() +
                    " in table " + tableId.toString());
        }
        return false;
    }

    @Override
    public Collection<UpfInterface> getInterfaces() throws UpfProgrammableException {
        if (!setupBehaviour("getInterfaces()")) {
            return null;
        }
        ArrayList<UpfInterface> ifaces = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricInterface(flowRule)) {
                ifaces.add(upfTranslator.fabricEntryToInterface(flowRule));
            }
        }
        return ifaces;
    }

    @Override
    public void addGtpTunnelPeer(GtpTunnelPeer peer) throws UpfProgrammableException {
        if (!setupBehaviour("addGtpTunnelPeer()")) {
            return;
        }

        Pair<FlowRule, FlowRule> fabricGtpTunnelPeers = upfTranslator.gtpTunnelPeerToFabricEntry(
                peer, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing ingress and egress rules {}, {}",
                fabricGtpTunnelPeers.getLeft().toString(), fabricGtpTunnelPeers.getRight().toString());
        flowRuleService.applyFlowRules(fabricGtpTunnelPeers.getLeft(), fabricGtpTunnelPeers.getRight());
        log.debug("GTP tunnel peer added with flowIDs ingress={}, egress={}",
                fabricGtpTunnelPeers.getLeft().id().value(), fabricGtpTunnelPeers.getRight().id().value());
    }

    @Override
    public void removeGtpTunnelPeer(GtpTunnelPeer peer) throws UpfProgrammableException {
        if (!setupBehaviour("removeGtpTunnelPeer()")) {
            return;
        }

        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_TUN_PEER_ID, peer.tunPeerId())
                .build();

        // TODO: make it atomic
        removeEntry(match, FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS, false);
        removeEntry(match, FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS, false);
    }

    @Override
    public void addUeSession(UeSession ueSession) throws UpfProgrammableException {
        if (!setupBehaviour("addUeSession()")) {
            return;
        }
        FlowRule fabricUeSession = upfTranslator.ueSessionToFabricEntry(ueSession, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", ueSession.toString());
        flowRuleService.applyFlowRules(fabricUeSession);
        log.debug("UE session added with flowID {}", fabricUeSession.id().value());
    }

    @Override
    public void removeUeSession(UeSession ueSession) throws UpfProgrammableException {
        if (!setupBehaviour("removeUeSession()")) {
            return;
        }
        final PiCriterion match;
        final PiTableId tableId;

        if (ueSession.isUplink()) {
            match = PiCriterion.builder()
                    .matchExact(HDR_TEID, ueSession.teid().asArray())
                    .matchExact(HDR_TUNNEL_IPV4_DST, ueSession.ipv4Address().toInt())
                    .build();
            tableId = FABRIC_INGRESS_SPGW_UPLINK_SESSIONS;
        } else {
            match = PiCriterion.builder()
                    .matchExact(HDR_UE_ADDR, ueSession.ipv4Address().toInt())
                    .build();
            tableId = FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS;
        }

        log.info("Removing {}", ueSession.toString());
        removeEntry(match, tableId, false);
    }

    @Override
    public void addUpfTerminationRule(UpfTerminationRule upfTerminationRule) throws UpfProgrammableException {
        if (!setupBehaviour("addUpfTerminationRule()")) {
            return;
        }
        FlowRule fabricUpfTermination = upfTranslator.upfTerminationToFabricEntry(
                upfTerminationRule, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", upfTerminationRule.toString());
        flowRuleService.applyFlowRules(fabricUpfTermination);
        log.debug("UPF termination added with flowID {}", fabricUpfTermination.id().value());
    }

    @Override
    public void removeUpfTerminationRule(UpfTerminationRule upfTerminationRule) throws UpfProgrammableException {
        if (!setupBehaviour("removeUpfTerminationRule()")) {
            return;
        }
        final PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_UE_SESSION_ID, upfTerminationRule.ueSessionId().toInt())
                .build();
        final PiTableId tableId = upfTerminationRule.isUplink() ?
                FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS :
                FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS;

        log.info("Removing {}", upfTerminationRule.toString());
        removeEntry(match, tableId, false);
    }

    @Override
    public void removeInterface(UpfInterface upfInterface) throws UpfProgrammableException {
        if (!setupBehaviour("removeInterface()")) {
            return;
        }
        Ip4Prefix ifacePrefix = upfInterface.getPrefix();
        if (upfInterface.isCore()) {
            applyUplinkRecirculation(ifacePrefix, true);
        }
        // If it isn't a core interface (so it is either access/dbuf or unknown), try removing first
        // access/dbuf interfaces and then fall through in the next step where we try to remove the core flow
        if (!upfInterface.isCore()) {
            PiCriterion match1 = PiCriterion.builder()
                    .matchLpm(HDR_IPV4_DST_ADDR, ifacePrefix.address().toInt(),
                            ifacePrefix.prefixLength())
                    .matchExact(HDR_GTPU_IS_VALID, 1)
                    .build();
            // removeEntry does return false only for severe issues, before we had
            // a safe fall through. This part should not be affected since core and access
            // flows are different in the match keys and should not result in wrong removal
            removeEntry(match1, FABRIC_INGRESS_SPGW_INTERFACES, true);
        }
        // This additional step might be also needed in case of unknown interfaces
        PiCriterion match2 = PiCriterion.builder()
                .matchLpm(HDR_IPV4_DST_ADDR, ifacePrefix.address().toInt(),
                        ifacePrefix.prefixLength())
                .matchExact(HDR_GTPU_IS_VALID, 0)
                .build();
        removeEntry(match2, FABRIC_INGRESS_SPGW_INTERFACES, false);
    }

    private void applyUplinkRecirculation(Ip4Prefix subnet, boolean remove) {
        log.warn("{} uplink recirculation rules on {} for subnet {}",
                remove ? "Removing" : "Installing", deviceId, subnet);
        // By default deny all uplink traffic with IP dst on the given UE subnet
        FlowRule denyRule = upfTranslator.buildFabricUplinkRecircEntry(
                deviceId, appId, null, subnet, false, DEFAULT_PRIORITY);
        // Allow recirculation only for packets with source on the same UE subnet
        FlowRule allowRule = upfTranslator.buildFabricUplinkRecircEntry(
                deviceId, appId, subnet, subnet, true, DEFAULT_PRIORITY + 10);
        if (!remove) {
            flowRuleService.applyFlowRules(denyRule, allowRule);
        } else {
            flowRuleService.removeFlowRules(denyRule, allowRule);
        }
    }
}
