// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import org.onlab.packet.Ip4Prefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.drivers.p4runtime.AbstractP4RuntimeHandlerBehaviour;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.upf.ForwardingActionRule;
import org.onosproject.net.behaviour.upf.PacketDetectionRule;
import org.onosproject.net.behaviour.upf.PdrStats;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfProgrammable;
import org.onosproject.net.behaviour.upf.UpfProgrammableException;
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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.onosproject.net.pi.model.PiCounterType.INDIRECT;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_ENCAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_PDR_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_QUEUES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_SET_QUEUE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_PDRS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_FARS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_INTERFACES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_PDR_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_PDRS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_FAR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_GTPU_IS_VALID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_IPV4_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_SLICE_TC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUNNEL_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.QID;

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
    protected FabricUpfStore fabricUpfStore;
    protected FabricUpfTranslator upfTranslator;

    private long farTableSize;
    private long encappedPdrTableSize;
    private long unencappedPdrTableSize;
    private long pdrCounterSize;

    private ApplicationId appId;

    static final SliceId SLICE_MOBILE = SliceId.MAX_SLICE_ID;

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
        fabricUpfStore = handler().get(DistributedFabricUpfStore.class);
        upfTranslator = new FabricUpfTranslator(fabricUpfStore);
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
            slicingService.addSlice(SLICE_MOBILE);
            try {
                Set<TrafficClass> tcs = slicingService.getTrafficClasses(SLICE_MOBILE);
                Arrays.stream(TrafficClass.values()).forEach(tc -> {
                    if (tcs.contains(tc) || tc.equals(TrafficClass.BEST_EFFORT) ||
                            tc.equals(TrafficClass.SYSTEM)) {
                        return;
                    }
                    slicingService.addTrafficClass(SLICE_MOBILE, tc);
                });
            } catch (SlicingException e) {
                log.error("Exception while configuring traffic class for Mobile Slice: {}", e.getMessage());
                return false;
            }
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
     * Grab the capacities for the PDR and FAR tables from the pipeconf. Runs only once, on initialization.
     *
     * @return true if resource is fetched successfully, false otherwise.
     * @throws IllegalStateException when FAR or PDR table can't be found in the pipeline model.
     */
    private boolean computeHardwareResourceSizes() {
        long farTableSize = 0;
        long encappedPdrTableSize = 0;
        long unencappedPdrTableSize = 0;

        // Get table sizes of interest
        for (PiTableModel piTable : pipeconf.pipelineModel().tables()) {
            if (piTable.id().equals(FABRIC_INGRESS_SPGW_UPLINK_PDRS)) {
                encappedPdrTableSize = piTable.maxSize();
            } else if (piTable.id().equals(FABRIC_INGRESS_SPGW_DOWNLINK_PDRS)) {
                unencappedPdrTableSize = piTable.maxSize();
            } else if (piTable.id().equals(FABRIC_INGRESS_SPGW_FARS)) {
                farTableSize = piTable.maxSize();
            }
        }
        if (encappedPdrTableSize == 0) {
            throw new IllegalStateException("Unable to find uplink PDR table in pipeline model.");
        }
        if (unencappedPdrTableSize == 0) {
            throw new IllegalStateException("Unable to find downlink PDR table in pipeline model.");
        }
        if (encappedPdrTableSize != unencappedPdrTableSize) {
            log.warn("The uplink and downlink PDR tables don't have equal sizes! Using the minimum of the two.");
        }
        if (farTableSize == 0) {
            throw new IllegalStateException("Unable to find FAR table in pipeline model.");
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
        this.farTableSize = farTableSize;
        this.encappedPdrTableSize = encappedPdrTableSize;
        this.unencappedPdrTableSize = unencappedPdrTableSize;
        this.pdrCounterSize = Math.min(ingressCounterSize, egressCounterSize);
        return true;
    }

    @Override
    public void enablePscEncap(int defaultQfi) {
        if (!setupBehaviour("enablePscEncap()")) {
            return;
        }
        if (pipeconf.pipelineModel().table(FABRIC_EGRESS_SPGW_GTPU_ENCAP).isEmpty()) {
            log.error("Missing {} table in {}, cannot enable PSC encap",
                      FABRIC_EGRESS_SPGW_GTPU_ENCAP, deviceId);
            return;
        }
        flowRuleService.applyFlowRules(upfTranslator.buildGtpuWithPscEncapRule(
                deviceId, appId, defaultQfi));
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
        slicingService.removeTrafficClass(SLICE_MOBILE, TrafficClass.ELASTIC);
        slicingService.removeTrafficClass(SLICE_MOBILE, TrafficClass.REAL_TIME);
        slicingService.removeTrafficClass(SLICE_MOBILE, TrafficClass.CONTROL);
        slicingService.removeSlice(SLICE_MOBILE);
        fabricUpfStore.reset();
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
        log.info("Clearing all UE sessions.");
        int pdrsCleared = 0;
        int farsCleared = 0;
        for (FlowRule entry : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricPdr(entry)) {
                pdrsCleared++;
                flowRuleService.removeFlowRules(entry);
            } else if (upfTranslator.isFabricFar(entry)) {
                farsCleared++;
                flowRuleService.removeFlowRules(entry);
            }
        }
        log.info("Cleared {} PDRs and {} FARS.", pdrsCleared, farsCleared);
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
    public long pdrCounterSize() {
        if (!setupBehaviour("pdrCounterSize()")) {
            return -1;
        }
        return pdrCounterSize;
    }

    @Override
    public long farTableSize() {
        if (!setupBehaviour("farTableSize()")) {
            return -1;
        }
        return farTableSize;
    }

    @Override
    public long pdrTableSize() {
        if (!setupBehaviour("pdrTableSize()")) {
            return -1;
        }
        return Math.min(encappedPdrTableSize, unencappedPdrTableSize) * 2;
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
    public void addPdr(PacketDetectionRule pdr) throws UpfProgrammableException {
        if (!setupBehaviour("addPdr()")) {
            return;
        }
        if (pdr.counterId() >= pdrCounterSize() || pdr.counterId() < 0) {
            throw new UpfProgrammableException("Counter cell index referenced by PDR is out of bounds.",
                    UpfProgrammableException.Type.COUNTER_INDEX_OUT_OF_RANGE);
        }
        FlowRule fabricPdr = upfTranslator.pdrToFabricEntry(pdr, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", pdr.toString());
        flowRuleService.applyFlowRules(fabricPdr);
        log.debug("PDR added with flowID {}", fabricPdr.id().value());
    }


    @Override
    public void addFar(ForwardingActionRule far) throws UpfProgrammableException {
        if (!setupBehaviour("addFar()")) {
            return;
        }
        FlowRule fabricFar = upfTranslator.farToFabricEntry(far, deviceId, appId, DEFAULT_PRIORITY);
        log.info("Installing {}", far.toString());
        flowRuleService.applyFlowRules(fabricFar);
        log.debug("FAR added with flowID {}", fabricFar.id().value());
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
    public Collection<PacketDetectionRule> getPdrs() throws UpfProgrammableException {
        if (!setupBehaviour("getPdrs()")) {
            return null;
        }
        ArrayList<PacketDetectionRule> pdrs = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricPdr(flowRule)) {
                pdrs.add(upfTranslator.fabricEntryToPdr(flowRule));
            }
        }
        return pdrs;
    }

    @Override
    public Collection<ForwardingActionRule> getFars() throws UpfProgrammableException {
        if (!setupBehaviour("getFars()")) {
            return null;
        }
        ArrayList<ForwardingActionRule> fars = new ArrayList<>();
        for (FlowRule flowRule : flowRuleService.getFlowEntries(deviceId)) {
            if (upfTranslator.isFabricFar(flowRule)) {
                fars.add(upfTranslator.fabricEntryToFar(flowRule));
            }
        }
        return fars;
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
    public void removePdr(PacketDetectionRule pdr) throws UpfProgrammableException {
        if (!setupBehaviour("removePdr()")) {
            return;
        }
        final PiCriterion match;
        final PiTableId tableId;
        if (pdr.matchesEncapped()) {
            match = PiCriterion.builder()
                    .matchExact(HDR_TEID, pdr.teid().asArray())
                    .matchExact(HDR_TUNNEL_IPV4_DST, pdr.tunnelDest().toInt())
                    .build();
            tableId = FABRIC_INGRESS_SPGW_UPLINK_PDRS;
        } else {
            match = PiCriterion.builder()
                    .matchExact(HDR_UE_ADDR, pdr.ueAddress().toInt())
                    .build();
            tableId = FABRIC_INGRESS_SPGW_DOWNLINK_PDRS;
        }
        log.info("Removing {}", pdr.toString());
        removeEntry(match, tableId, false);
    }

    @Override
    public void removeFar(ForwardingActionRule far) throws UpfProgrammableException {
        if (!setupBehaviour("removeFar()")) {
            return;
        }
        log.info("Removing {}", far.toString());

        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_FAR_ID, fabricUpfStore.removeGlobalFarId(far.sessionId(), far.farId()))
                .build();

        removeEntry(match, FABRIC_INGRESS_SPGW_FARS, false);
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
