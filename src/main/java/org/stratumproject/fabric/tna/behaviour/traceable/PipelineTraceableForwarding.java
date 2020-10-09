// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.onlab.packet.MacAddress;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.PipelineTraceablePacket;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.MplsCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.pi.model.PiMatchType;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiFieldMatch;
import org.onosproject.net.pi.runtime.PiLpmFieldMatch;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.service.PiTranslationException;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterion;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterionNotNull;

/**
 * Implementation of the forwarding control block for fabric-tna.
 */
class PipelineTraceableForwarding extends AbstractPipelineTraceableCtrl {

    // Maps the table to the respective fwd type. Used for an early discards of the flow rules
    // FIXME support IPv6
    private static final ImmutableMap<PiTableId, Byte> FWD_TYPE_MAP = ImmutableMap.<PiTableId, Byte>builder()
            .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING, FabricTraceableMetadata.FWD_BRIDGING)
            .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS, FabricTraceableMetadata.FWD_MPLS)
            .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4, FabricTraceableMetadata.FWD_IPV4_UNICAST)
            .build();

    /**
     * Creates a new instance with the given capabilities.
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     * @param piTranslationService pi translation service
     */
    public PipelineTraceableForwarding(FabricCapabilities capabilities, PiPipeconf pipeconf,
                                       PiTranslationService piTranslationService) {
        super(capabilities, pipeconf, piTranslationService, DataPlaneEntity.Type.FLOWRULE);
        // FIXME support IPv6
        this.tableIds = Lists.newArrayList(
                P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING,
                P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS,
                P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4
        );
    }

    @Override
    public PipelineTraceableOutput apply(PipelineTraceableInput input) {
        FabricTraceableMetadata.Builder metadataBuilder = getMetadata(input.ingressPacket());
        TrafficSelector packet = input.ingressPacket().packet();
        PipelineTraceableOutput.Builder outputBuilder = PipelineTraceableOutput.builder();
        PipelineTraceableHitChain currentHitChain = PipelineTraceableHitChain.emptyHitChain();
        PipelineTraceablePacket egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().packet(), metadataBuilder.build());

        // Skips forwarding if the relative metadata is set.
        // Note that this is not a failure.
        if (metadataBuilder.build().isSkipFwd()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.pass();
            return outputBuilder.appendToLog("Skip " + getClass().getSimpleName())
                    .addHitChain(currentHitChain)
                    .build();
        }

        List<DataPlaneEntity> forwardingFlows = getDataPlaneEntity(input.deviceState());
        if (forwardingFlows.isEmpty()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.dropped();
            return outputBuilder.appendToLog("There are no flows for " + getClass().getSimpleName() +
                    ". Aborting")
                    .noFlows()
                    .addHitChain(currentHitChain)
                    .build();
        }

        List<PiTableEntry> matchedTableEntries = Lists.newArrayList();
        PiTableEntry bestLpm = null;
        PiTableEntry bestTer = null;
        Map<PiTableEntry, DataPlaneEntity> mapping = Maps.newHashMap();
        for (DataPlaneEntity dataPlaneEntity : forwardingFlows) {

            // Quick check based on the fwd type
            FlowEntry flowEntry = dataPlaneEntity.getFlowEntry();
            if (metadataBuilder.build().getFwdType() != FWD_TYPE_MAP.get(flowEntry.table())) {
                if (log.isDebugEnabled()) {
                    log.debug("Skips flow rule belonging to a different table");
                }
                continue;
            }

            if (log.isDebugEnabled()) {
                log.debug("Packet before forwarding augmentation {}", packet);
            }
            TrafficSelector packetForPiTranslation = augmentPacket(packet, metadataBuilder.build(),
                    dataPlaneEntity);
            if (packetForPiTranslation.equals(DefaultTrafficSelector.emptySelector())) {
                log.debug("matchForwardingTables failed due to augmentation error");
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("Packet after forwarding augmentation {}", packetForPiTranslation);
            }

            // Actual matching logic
            PiTableEntry tableEntry = matchTables(packetForPiTranslation, dataPlaneEntity);
            // Mpls tables are basically exact matches; they can be directly
            // stored. Instead, lpm and ternary entries can have conflicts -
            // an additional step needs to be performed to select the best entry.
            if (tableEntry != null) {
                if (tableEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING)) {
                    bestTer = TraceableUtils.selectBestTerEntry(bestTer, tableEntry);
                    mapping.put(tableEntry, dataPlaneEntity);
                } else if (tableEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)) {
                    bestLpm = TraceableUtils.selectBestLpmEntry(bestLpm, tableEntry);
                    mapping.put(tableEntry, dataPlaneEntity);
                } else if (tableEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V6)) {
                    // FIXME support IPv6
                    log.warn("IPv6 is not yet supported");
                } else {
                        matchedTableEntries.add(tableEntry);
                        currentHitChain.addDataPlaneEntity(dataPlaneEntity);
                }
            }
        }

        // If there was a match, let's add them to the matched entries.
        // We use the mapping to retrieve the dataplane entity
        if (bestTer != null) {
            matchedTableEntries.add(bestTer);
            currentHitChain.addDataPlaneEntity(mapping.get(bestTer));
        }
        if (bestLpm != null) {
            matchedTableEntries.add(bestLpm);
            currentHitChain.addDataPlaneEntity(mapping.get(bestLpm));
        }

        matchedTableEntries.forEach(matchedTableEntry -> applyTables(metadataBuilder, matchedTableEntry));

        egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().packet(), metadataBuilder.build());
        currentHitChain.setEgressPacket(egressPacket);
        currentHitChain.pass();
        return outputBuilder.addHitChain(currentHitChain)
                .build();
    }

    @Override
    public PiTableEntry matchTables(TrafficSelector packetForPiTranslation, DataPlaneEntity dataPlaneEntity) {
        FlowEntry flowEntry = dataPlaneEntity.getFlowEntry();
        FlowRule packetFlow = createFlowForPiTranslation(flowEntry, packetForPiTranslation)
                .build();

        try {
            PiTableEntry packetTranslated =
                    piTranslationService.flowRuleTranslator().translate(packetFlow, pipeconf);
            PiTableEntry matchFlowTranslated =
                    piTranslationService.flowRuleTranslator().translate(flowEntry, pipeconf);
            return matchFlowTranslated.matchKey().fieldMatches().stream()
                    .allMatch(fieldMatch -> {
                        // Lpm matching -> routing tables
                        if (Objects.equals(fieldMatch.type(), PiMatchType.LPM)) {
                            // We should find the relative lpm match of the packet
                            PiFieldMatch tobeMatched = packetTranslated.matchKey().fieldMatches().stream()
                                    .filter(matches -> Objects.equals(matches.type(), PiMatchType.LPM) &&
                                            Objects.equals(fieldMatch.fieldId(), matches.fieldId()))
                                    .findFirst()
                                    .orElse(null);
                            return TraceableUtils.lpmMatch((PiLpmFieldMatch) fieldMatch, (PiLpmFieldMatch) tobeMatched);
                        } else {
                            // Bridging and mpls tables. Note this is a simplification:
                            // We can potentially use ternaryMatch() implementation
                            return packetTranslated.matchKey().fieldMatches().contains(fieldMatch);
                        }
                    }) ? matchFlowTranslated : null;
        } catch (PiTranslationException e) {
            log.debug("matchForwardingTables failed due to PI translation error: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public TrafficSelector augmentPacket(TrafficSelector packet, FabricTraceableMetadata metadata,
                                         DataPlaneEntity dataPlaneEntity) {
        FlowEntry flowEntry = dataPlaneEntity.getFlowEntry();
        TrafficSelector.Builder packetWithMetadata = DefaultTrafficSelector.builder(packet);
        TrafficSelector.Builder packetForPiTranslation = DefaultTrafficSelector.builder();
        PiCriterion.Builder piCriterionForTranslation = PiCriterion.builder();
        // The augmentation step of this control block is very simple. Criteria are mostly the same,
        // actually some of them are not considered.
        if (flowEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING)) {
            // Adds Bridging table fields
            if (log.isDebugEnabled()) {
                log.debug("Augments packet with bridging selector");
            }
            // Bridging tables match on vlan id stored in the metadata
            packetWithMetadata.matchVlanId(metadata.getVlanId());
            TrafficSelector bridgingSelector = getBridingMatchingFields(packetWithMetadata.build(),
                    piCriterionForTranslation);
            bridgingSelector.criteria().forEach(packetForPiTranslation::add);
        } else if (flowEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)) {
            // Adds Routing table fields
            if (log.isDebugEnabled()) {
                log.debug("Augments packet with routing_v4 selector");
            }
            TrafficSelector routingSelector = getRoutingMatchingFields(packet, piCriterionForTranslation);
            routingSelector.criteria().forEach(packetForPiTranslation::add);
        } else if (flowEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V6)) {
            // FIXME support IPv6
            log.warn("Augmentation of the packet with routing_v6 selector is not yet supported");
        } else if (flowEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS)) {
            // Adds Mpls table fields
            if (log.isDebugEnabled()) {
                log.debug("Augments packet with mpls selector");
            }
            TrafficSelector mplsSelector = getMplsMatchingFields(packet, piCriterionForTranslation);
            mplsSelector.criteria().forEach(packetForPiTranslation::add);
        } else {
            return packetForPiTranslation.build();
        }

        try {
            PiCriterion piCriterion = piCriterionForTranslation.build();
            return packetForPiTranslation.matchPi(piCriterion)
                    .build();
        } catch (IllegalArgumentException e) {
            log.debug("PiCriterion is empty");
        }
        return packetForPiTranslation.build();
    }

    @Override
    public void applyTables(FabricTraceableMetadata.Builder metadataBuilder, PiTableEntry piTableEntry) {
        // FIXME support for IPv6
        if (piTableEntry.action().type() == PiTableAction.Type.ACTION) {
            PiAction piAction = (PiAction) piTableEntry.action();
            if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_BRIDGING) ||
                    piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V4)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyForwardingTables action {} {}", piAction.id(), piAction.parameters());
                }
                metadataBuilder.setNextId(getNextIdFromParams(piAction.parameters()));
            } else if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_FORWARDING_POP_MPLS_AND_NEXT)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyForwardingTables action POP_MPLS {}", piAction.parameters());
                }
                // The metadata inside the packet selector contains the original ethType
                // we extract only the next id and reset the mpls label
                metadataBuilder.setNextId(getNextIdFromParams(piAction.parameters()));
                metadataBuilder.setMplsLabel(0);
            } else {
                log.warn("applyForwardingTables does not support action: {}", piAction);
            }
        } else {
            log.warn("applyForwardingTables does not support actions different from : {}",
                    PiAction.Type.ACTION);
        }
    }

    private TrafficSelector getRoutingMatchingFields(TrafficSelector packet,
                                                     PiCriterion.Builder piCriterionBuilder) {
        // Special treatment for the default route
        final IPCriterion ipDstCriterion = (IPCriterion) criterionNotNull(
                packet.criteria(), Criterion.Type.IPV4_DST);
        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);

        // Get the pi criterion and copy in the builder
        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionBuilder::add);
        }

        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        // if it is null or it is not the default route
        if (ipDstCriterion != null && ipDstCriterion.ip().prefixLength() != 0) {
            selector.add(ipDstCriterion);
        }
        return selector.build();
    }

    private TrafficSelector getBridingMatchingFields(TrafficSelector packet,
                                                     PiCriterion.Builder piCriterionBuilder) {
        // Special treatment for the broadcast
        final VlanIdCriterion vlanIdCriterion = (VlanIdCriterion) criterion(
                packet.criteria(), Criterion.Type.VLAN_VID);
        final EthCriterion ethDstCriterion = (EthCriterion) criterion(
                packet.criteria(), Criterion.Type.ETH_DST);
        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);

        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionBuilder::add);
        }

        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        if (vlanIdCriterion != null) {
            selector.add(vlanIdCriterion);
        }
        // if it is not broadcast
        if (ethDstCriterion != null && !ethDstCriterion.mac().equals(MacAddress.NONE)) {
            selector.matchEthDstMasked(ethDstCriterion.mac(), MacAddress.EXACT_MASK);
        }
        return selector.build();
    }

    private TrafficSelector getMplsMatchingFields(TrafficSelector packet,
                                       PiCriterion.Builder piCriterionBuilder) {
        final MplsCriterion mplsCriterion = (MplsCriterion) criterionNotNull(
                packet.criteria(), Criterion.Type.MPLS_LABEL);
        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);

        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionBuilder::add);
        }

        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        if (mplsCriterion != null) {
            selector.add(mplsCriterion);
        }
        return selector.build();
    }


}
