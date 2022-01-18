// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.Ip4Prefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.drivers.p4runtime.AbstractP4RuntimeHandlerBehaviour;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.upf.GtpTunnelPeer;
import org.onosproject.net.behaviour.upf.SessionDownlink;
import org.onosproject.net.behaviour.upf.SessionUplink;
import org.onosproject.net.behaviour.upf.UpfCounter;
import org.onosproject.net.behaviour.upf.UpfEntity;
import org.onosproject.net.behaviour.upf.UpfEntityType;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfProgrammable;
import org.onosproject.net.behaviour.upf.UpfProgrammableException;
import org.onosproject.net.behaviour.upf.UpfTerminationDownlink;
import org.onosproject.net.behaviour.upf.UpfTerminationUplink;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.model.PiTableModel;
import org.onosproject.net.pi.runtime.PiCounterCell;
import org.onosproject.net.pi.runtime.PiCounterCellHandle;
import org.onosproject.net.pi.runtime.PiCounterCellId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.Constants;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.onosproject.net.pi.model.PiCounterType.INDIRECT;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_ENCAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_TERMINATIONS_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_INTERFACES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_TERMINATIONS_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_GTPU_IS_VALID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_IPV4_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUNNEL_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUN_PEER_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_SESSION_ID;

/**
 * Implementation of a UPF programmable device behavior.
 */
public class FabricUpfProgrammable extends AbstractP4RuntimeHandlerBehaviour
        implements UpfProgrammable {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private static final int DEFAULT_PRIORITY = 128;
    private static final long DEFAULT_P4_DEVICE_ID = 1;

    protected FlowRuleService flowRuleService;
    protected PacketService packetService;
    protected FabricUpfTranslator upfTranslator;

    private long interfaceTableSize;
    private long uplinkUeSessionsTableSize;
    private long downlinkUeSessionsTableSize;
    private long uplinkUpfTerminationsTableSize;
    private long downlinkUpfTerminationsTableSize;
    private long upfCounterSize;
    private long gtpTunnelPeersTableSize;

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
        packetService = handler().get(PacketService.class);
        upfTranslator = new FabricUpfTranslator();
        final CoreService coreService = handler().get(CoreService.class);
        appId = coreService.getAppId(Constants.APP_NAME_UPF);
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
            return true;
        }
        return false;
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
        long ingressGtpTunnelPeersTableSize = 0;
        long egressGtpTunnelPeersTableSize = 0;

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
            } else if (piTable.id().equals(FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS)) {
                ingressGtpTunnelPeersTableSize = piTable.maxSize();
            } else if (piTable.id().equals(FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS)) {
                egressGtpTunnelPeersTableSize = piTable.maxSize();
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
        if (ingressGtpTunnelPeersTableSize == 0) {
            throw new IllegalStateException("Unable to find ingress GTP tunnel peers table in pipeline model.");
        }
        if (egressGtpTunnelPeersTableSize == 0) {
            throw new IllegalStateException("Unable to find egress GTP tunnel peers table in pipeline model.");
        }
        if (ingressGtpTunnelPeersTableSize != egressGtpTunnelPeersTableSize) {
            log.warn("GTP tunnel peers ingress and egress table sizes are not equal! Using the minimum of the two.");
        }

        // Get counter sizes of interest
        long ingressCounterSize = 0;
        long egressCounterSize = 0;
        for (PiCounterModel piCounter : pipeconf.pipelineModel().counters()) {
            if (piCounter.id().equals(FABRIC_INGRESS_SPGW_TERMINATIONS_COUNTER)) {
                ingressCounterSize = piCounter.size();
            } else if (piCounter.id().equals(FABRIC_EGRESS_SPGW_TERMINATIONS_COUNTER)) {
                egressCounterSize = piCounter.size();
            }
        }
        if (ingressCounterSize != egressCounterSize) {
            log.warn("UPF ingress and egress counter sizes are not equal! Using the minimum of the two.");
        }

        this.uplinkUeSessionsTableSize = uplinkUeSessionsTableSize;
        this.downlinkUeSessionsTableSize = downlinkUeSessionsTableSize;
        this.uplinkUpfTerminationsTableSize = uplinkUpfTerminationsTableSize;
        this.downlinkUpfTerminationsTableSize = downlinkUpfTerminationsTableSize;
        this.upfCounterSize = Math.min(ingressCounterSize, egressCounterSize);
        this.gtpTunnelPeersTableSize = Math.min(ingressGtpTunnelPeersTableSize, egressGtpTunnelPeersTableSize);

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
    }

    @Override
    public void deleteAll(UpfEntityType entityType) throws UpfProgrammableException {
        if (!setupBehaviour("deleteAll()")) {
            return;
        }

        log.info(format("Clearing all UPF entities of type %s.", entityType.humanReadableName()));
        int entitiesCleared = 0;
        List<FlowRule> toBeRemoved = Lists.newArrayList();
        for (FlowRule entry : flowRuleService.getFlowEntries(deviceId)) {
            switch (entityType) {
                case INTERFACE:
                    if (upfTranslator.isFabricInterface(entry)) {
                        try {
                            UpfInterface iface = upfTranslator.fabricEntryToInterface(entry);
                            if (iface.isCore()) {
                                applyUplinkRecirculation(iface.prefix(), true);
                            }
                        } catch (UpfProgrammableException e) {
                            log.error("Error when translating interface entry, " +
                                              "will skip removing uplink recirculation rules: {} [{}]",
                                      e.getMessage(), entry);
                        }
                        toBeRemoved.add(entry);
                        entitiesCleared++;
                    }
                    break;
                case SESSION_UPLINK:
                    if (upfTranslator.isFabricUeSessionUplink(entry)) {
                        toBeRemoved.add(entry);
                        entitiesCleared++;
                    }
                    break;
                case SESSION_DOWNLINK:
                    if (upfTranslator.isFabricUeSessionDownlink(entry)) {
                        toBeRemoved.add(entry);
                        entitiesCleared++;
                    }
                    break;
                case TERMINATION_UPLINK:
                    if (upfTranslator.isFabricUpfTerminationUplink(entry)) {
                        toBeRemoved.add(entry);
                        entitiesCleared++;
                    }
                    break;
                case TERMINATION_DOWNLINK:
                    if (upfTranslator.isFabricUpfTerminationDownlink(entry)) {
                        toBeRemoved.add(entry);
                        entitiesCleared++;
                    }
                    break;
                case TUNNEL_PEER:
                    if (upfTranslator.isFabricGtpTunnelPeer(entry)) {
                        toBeRemoved.add(entry);
                        entitiesCleared++;
                    }
                    break;
                default:
                    log.warn("Unsupported entity type!");
                    break;
            }
        }
        flowRuleService.removeFlowRules(toBeRemoved.toArray(FlowRule[]::new));
        log.info("Cleared {} UPF entities of type {}", entitiesCleared, entityType.humanReadableName());
    }

    @Override
    public Collection<? extends UpfEntity> readAll(UpfEntityType entityType)
            throws UpfProgrammableException {
        if (!setupBehaviour("readAll()")) {
            return null;
        }

        switch (entityType) {
            case INTERFACE:
                return getInterfaces();
            case SESSION_UPLINK:
                return getUeSessionsUplink();
            case SESSION_DOWNLINK:
                return getUeSessionsDownlink();
            case TERMINATION_UPLINK:
                return getUpfTerminationsUplink();
            case TERMINATION_DOWNLINK:
                return getUpfTerminationsDownlink();
            case TUNNEL_PEER:
                return getGtpTunnelPeers();
            case COUNTER:
                return readCounters(-1);
            default:
                throw new UpfProgrammableException(format("Reading entity type %s not supported.",
                                                          entityType.humanReadableName()));
        }
    }

    private Collection<UpfEntity> getInterfaces() throws UpfProgrammableException {
        ArrayList<UpfEntity> ifaces = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricInterface(flowRule)) {
                ifaces.add(upfTranslator.fabricEntryToInterface(flowRule));
            }
        }
        return ifaces;
    }

    private Collection<UpfEntity> getGtpTunnelPeers() throws UpfProgrammableException {
        ArrayList<UpfEntity> gtpTunnelPeers = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricGtpTunnelPeer(flowRule)) {
                gtpTunnelPeers.add(upfTranslator.fabricEntryToGtpTunnelPeer(flowRule));
            }
        }
        return gtpTunnelPeers;
    }

    private Collection<UpfEntity> getUeSessionsUplink() throws UpfProgrammableException {
        ArrayList<UpfEntity> ueSessions = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricUeSessionUplink(flowRule)) {
                ueSessions.add(upfTranslator.fabricEntryToUeSessionUplink(flowRule));
            }
        }
        return ueSessions;
    }

    private Collection<UpfEntity> getUeSessionsDownlink() throws UpfProgrammableException {
        ArrayList<UpfEntity> ueSessions = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricUeSessionDownlink(flowRule)) {
                ueSessions.add(upfTranslator.fabricEntryToUeSessionDownlink(flowRule));
            }
        }
        return ueSessions;
    }

    private Collection<UpfEntity> getUpfTerminationsUplink() throws UpfProgrammableException {
        ArrayList<UpfEntity> upfTerminations = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricUpfTerminationUplink(flowRule)) {
                upfTerminations.add(upfTranslator.fabricEntryToUpfTerminationUplink(flowRule));
            }
        }
        return upfTerminations;
    }

    private Collection<UpfEntity> getUpfTerminationsDownlink() throws UpfProgrammableException {
        ArrayList<UpfEntity> upfTerminations = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricUpfTerminationDownlink(flowRule)) {
                upfTerminations.add(upfTranslator.fabricEntryToUpfTerminationDownlink(flowRule));
            }
        }
        return upfTerminations;
    }

    @Override
    public Collection<UpfCounter> readCounters(long maxCounterId) {
        if (!setupBehaviour("readCounters()")) {
            return null;
        }

        long counterSize = upfCounterSize;
        if (maxCounterId != -1) {
            counterSize = Math.min(maxCounterId, counterSize);
        }

        // Prepare UpfCounter object builders, one for each counter ID currently in use
        Map<Integer, UpfCounter.Builder> upfCounterBuilders = Maps.newHashMap();
        for (int cellId = 0; cellId < counterSize; cellId++) {
            upfCounterBuilders.put(cellId, UpfCounter.builder().withCellId(cellId));
        }

        // Generate the counter cell IDs.
        Set<PiCounterId> counterIds = ImmutableSet.of(
                FABRIC_INGRESS_SPGW_TERMINATIONS_COUNTER,
                FABRIC_EGRESS_SPGW_TERMINATIONS_COUNTER
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
            if (!upfCounterBuilders.containsKey((int) counterCell.cellId().index())) {
                // Most likely Up4config.maxUes() is set to a value smaller than what the switch
                // pipeline can hold.
                log.debug("Unrecognized index {} when reading all counters, " +
                                  "that's expected if we are manually limiting maxUes", counterCell);
                return;
            }
            UpfCounter.Builder statsBuilder = upfCounterBuilders.get((int) counterCell.cellId().index());
            if (counterCell.cellId().counterId().equals(FABRIC_INGRESS_SPGW_TERMINATIONS_COUNTER)) {
                statsBuilder.setIngress(counterCell.data().packets(),
                                        counterCell.data().bytes());
            } else if (counterCell.cellId().counterId().equals(FABRIC_EGRESS_SPGW_TERMINATIONS_COUNTER)) {
                statsBuilder.setEgress(counterCell.data().packets(),
                                       counterCell.data().bytes());
            } else {
                log.warn("Unrecognized counter ID {}, skipping", counterCell);
            }
        });

        return upfCounterBuilders
                .values()
                .stream()
                .map(UpfCounter.Builder::build)
                .collect(Collectors.toList());
    }

    @Override
    public long tableSize(UpfEntityType entityType) throws UpfProgrammableException {
        if (!setupBehaviour("tableSize()")) {
            return -1;
        }

        switch (entityType) {
            case INTERFACE:
                return interfaceTableSize;
            case TUNNEL_PEER:
                return gtpTunnelPeersTableSize;
            case SESSION_UPLINK:
                return this.uplinkUeSessionsTableSize;
            case SESSION_DOWNLINK:
                return this.downlinkUeSessionsTableSize;
            case TERMINATION_UPLINK:
                return this.uplinkUpfTerminationsTableSize;
            case TERMINATION_DOWNLINK:
                return this.downlinkUpfTerminationsTableSize;
            case COUNTER:
                return upfCounterSize;
            default:
                throw new UpfProgrammableException(format("Getting size of entity type %s not supported.",
                                                          entityType.humanReadableName()));
        }
    }

    @Override
    public UpfCounter readCounter(int cellId) throws UpfProgrammableException {
        if (!setupBehaviour("readCounter()")) {
            return null;
        }
        if (cellId >= upfCounterSize || cellId < 0) {
            throw new UpfProgrammableException("Requested UPF counter cell index is out of bounds.",
                                               UpfProgrammableException.Type.ENTITY_OUT_OF_RANGE);
        }
        UpfCounter.Builder stats = UpfCounter.builder().withCellId(cellId);

        // Make list of cell handles we want to read.
        List<PiCounterCellHandle> counterCellHandles = List.of(
                PiCounterCellHandle.of(deviceId,
                                       PiCounterCellId.ofIndirect(FABRIC_INGRESS_SPGW_TERMINATIONS_COUNTER, cellId)),
                PiCounterCellHandle.of(deviceId,
                                       PiCounterCellId.ofIndirect(FABRIC_EGRESS_SPGW_TERMINATIONS_COUNTER, cellId)));

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
            if (counterCell.cellId().counterId().equals(FABRIC_INGRESS_SPGW_TERMINATIONS_COUNTER)) {
                stats.setIngress(counterCell.data().packets(), counterCell.data().bytes());
            } else if (counterCell.cellId().counterId().equals(FABRIC_EGRESS_SPGW_TERMINATIONS_COUNTER)) {
                stats.setEgress(counterCell.data().packets(), counterCell.data().bytes());
            } else {
                log.warn("Unrecognized counter ID {}, skipping", counterCell);
            }
        });
        return stats.build();
    }

    @Override
    public void apply(UpfEntity entity) throws UpfProgrammableException {
        if (!setupBehaviour("apply()")) {
            return;
        }

        switch (entity.type()) {
            case INTERFACE:
                addInterface((UpfInterface) entity);
                break;
            case SESSION_UPLINK:
                addUeSessionUplink((SessionUplink) entity);
                break;
            case SESSION_DOWNLINK:
                addUeSessionDownlink((SessionDownlink) entity);
                break;
            case TERMINATION_UPLINK:
                addUpfTerminationUplink((UpfTerminationUplink) entity);
                break;
            case TERMINATION_DOWNLINK:
                addUpfTerminationDownlink((UpfTerminationDownlink) entity);
                break;
            case TUNNEL_PEER:
                addGtpTunnelPeer((GtpTunnelPeer) entity);
                break;
            case COUNTER:
            default:
                throw new UpfProgrammableException(format("Adding entity type %s not supported.",
                                                          entity.type().humanReadableName()));
        }
    }

    private void addInterface(UpfInterface upfInterface) throws UpfProgrammableException {
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

    private void addGtpTunnelPeer(GtpTunnelPeer peer) throws UpfProgrammableException {
        Pair<FlowRule, FlowRule> fabricGtpTunnelPeers = upfTranslator.gtpTunnelPeerToFabricEntry(
                peer, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing ingress and egress rules {}, {}",
                 fabricGtpTunnelPeers.getLeft().toString(), fabricGtpTunnelPeers.getRight().toString());
        flowRuleService.applyFlowRules(fabricGtpTunnelPeers.getLeft(), fabricGtpTunnelPeers.getRight());
        log.debug("GTP tunnel peer added with flowIDs ingress={}, egress={}",
                  fabricGtpTunnelPeers.getLeft().id().value(), fabricGtpTunnelPeers.getRight().id().value());
    }

    private void addUeSessionUplink(SessionUplink ueSession) throws UpfProgrammableException {
        FlowRule fabricUeSession = upfTranslator.sessionUplinkToFabricEntry(
                ueSession, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", ueSession.toString());
        flowRuleService.applyFlowRules(fabricUeSession);
        log.debug("Uplink UE session added with flowID {}", fabricUeSession.id().value());
    }

    private void addUeSessionDownlink(SessionDownlink ueSession) throws UpfProgrammableException {
        FlowRule fabricUeSession = upfTranslator.sessionDownlinkToFabricEntry(
                ueSession, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", ueSession.toString());
        flowRuleService.applyFlowRules(fabricUeSession);
        log.debug("Downlink UE session added with flowID {}", fabricUeSession.id().value());
    }

    private void addUpfTerminationUplink(UpfTerminationUplink upfTermination) throws UpfProgrammableException {
        FlowRule fabricUpfTermination = upfTranslator.upfTerminationUplinkToFabricEntry(
                upfTermination, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", upfTermination.toString());
        flowRuleService.applyFlowRules(fabricUpfTermination);
        log.debug("Uplink UPF termination added with flowID {}", fabricUpfTermination.id().value());
    }

    private void addUpfTerminationDownlink(UpfTerminationDownlink upfTermination) throws UpfProgrammableException {
        FlowRule fabricUpfTermination = upfTranslator.upfTerminationDownlinkToFabricEntry(
                upfTermination, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", upfTermination.toString());
        flowRuleService.applyFlowRules(fabricUpfTermination);
        log.debug("Downlink UPF termination added with flowID {}", fabricUpfTermination.id().value());
    }

    @Override
    public void delete(UpfEntity entity) throws UpfProgrammableException {
        if (!setupBehaviour("delete()")) {
            return;
        }

        switch (entity.type()) {
            case INTERFACE:
                removeInterface((UpfInterface) entity);
                break;
            case SESSION_UPLINK:
                removeSessionUplink((SessionUplink) entity);
                break;
            case SESSION_DOWNLINK:
                removeSessionDownlink((SessionDownlink) entity);
                break;
            case TERMINATION_UPLINK:
                removeUpfTerminationUplink((UpfTerminationUplink) entity);
                break;
            case TERMINATION_DOWNLINK:
                removeUpfTerminationDownlink((UpfTerminationDownlink) entity);
                break;
            case TUNNEL_PEER:
                removeGtpTunnelPeer((GtpTunnelPeer) entity);
                break;
            case COUNTER:
            default:
                throw new UpfProgrammableException(format("Deleting entity type %s not supported.",
                                                          entity.type().humanReadableName()));
        }
    }

    private boolean removeEntry(PiCriterion match, PiTableId tableId, boolean failSilent)
            throws UpfProgrammableException {
        return removeEntries(Lists.newArrayList(Pair.of(tableId, match)), failSilent);
    }

    private boolean removeEntries(Collection<Pair<PiTableId, PiCriterion>> entriesToRemove, boolean failSilent)
            throws UpfProgrammableException {
        Collection<FlowRule> entries = entriesToRemove.stream().map(e -> DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(e.getKey())
                .withSelector(DefaultTrafficSelector.builder().matchPi(e.getValue()).build())
                .withPriority(DEFAULT_PRIORITY)
                .build())
                .collect(Collectors.toList());

        try {
            flowRuleService.removeFlowRules(entries.toArray(FlowRule[]::new));
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
            String errorString = entriesToRemove.stream()
                    .map(e -> "    Match: " + e.getValue() + " Table: " + e.getKey() + "\n")
                    .collect(Collectors.joining());
            throw new UpfProgrammableException("Unable to remove FlowRules\n " + errorString);
        }
        return false;
    }

    private void removeInterface(UpfInterface upfInterface) throws UpfProgrammableException {
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

    private void removeSessionUplink(SessionUplink ueSession) throws UpfProgrammableException {
        final PiCriterion match;

        match = PiCriterion.builder()
                .matchExact(HDR_TEID, ueSession.teid())
                .matchExact(HDR_TUNNEL_IPV4_DST, ueSession.tunDstAddr().toOctets())
                .build();
        log.info("Removing {}", ueSession);
        removeEntry(match, FABRIC_INGRESS_SPGW_UPLINK_SESSIONS, false);
    }

    private void removeSessionDownlink(SessionDownlink ueSession) throws UpfProgrammableException {
        final PiCriterion match;

        match = PiCriterion.builder()
                .matchExact(HDR_UE_ADDR, ueSession.ueAddress().toOctets())
                .build();

        log.info("Removing {}", ueSession.toString());
        removeEntry(match, FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS, false);
    }

    private void removeUpfTerminationUplink(UpfTerminationUplink upfTermination)
            throws UpfProgrammableException {
        final PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_UE_SESSION_ID, upfTermination.ueSessionId().toInt())
                .build();

        log.info("Removing {}", upfTermination.toString());
        removeEntry(match, FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS, false);
    }

    private void removeUpfTerminationDownlink(UpfTerminationDownlink upfTermination)
            throws UpfProgrammableException {
        final PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_UE_SESSION_ID, upfTermination.ueSessionId().toInt())
                .build();

        log.info("Removing {}", upfTermination.toString());
        removeEntry(match, FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS, false);
    }

    private void removeGtpTunnelPeer(GtpTunnelPeer peer) throws UpfProgrammableException {
        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_TUN_PEER_ID, peer.tunPeerId())
                .build();
        removeEntries(Lists.newArrayList(Pair.of(FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS, match),
                                         Pair.of(FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS, match)),
                      false);
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
